// Package plugin provides a shared host runtime for alpamon plugins.
//
// It encapsulates the boilerplate that every plugin previously duplicated:
// signal handling, pidfile management, config loading, session setup, the
// initial server-side version handshake, and the websocket lifecycle
// (graceful shutdown plus in-place restart).
//
// A plugin defines a Plugin value and either calls Plugin.Run directly or
// embeds it under a Cobra root command via NewRootCmd.
package plugin

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/alpacax/alpamon/v2/cmd/alpamon/command/setup"
	"github.com/alpacax/alpamon/v2/internal/pool"
	"github.com/alpacax/alpamon/v2/pkg/agent"
	"github.com/alpacax/alpamon/v2/pkg/config"
	"github.com/alpacax/alpamon/v2/pkg/pidfile"
	"github.com/alpacax/alpamon/v2/pkg/runner"
	"github.com/alpacax/alpamon/v2/pkg/scheduler"
	"github.com/alpacax/alpamon/v2/pkg/utils"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

// shutdownTimeout bounds how long the SDK waits for the worker pool to drain.
const shutdownTimeout = 30 * time.Second

// exitRestart is the internal sentinel exit code used by run to signal that
// Run should exec the binary in place after deferred cleanup completes.
const exitRestart = -1

// Plugin describes a plugin agent. Name, Version, WSPath, CheckServerURL and
// Build are required; the rest are optional.
type Plugin struct {
	// Name is the plugin's binary/service name, e.g. "alpamon-dhcp-plugin".
	// Used for the pidfile, logging, and config file lookup.
	Name string

	// Version is the plugin's version string (sent in the initial handshake).
	Version string

	// WSPath is the websocket route used for the main backhaul connection,
	// e.g. "/ws/dhcp/backhaul/".
	WSPath string

	// ControlWSPath is the optional control-channel websocket route.
	// Most plugins leave this empty.
	ControlWSPath string

	// CheckServerURL is the HTTP path PATCHed during the version handshake
	// before opening the websocket, e.g. "/api/dhcp/-/".
	CheckServerURL string

	// InitLogger is called once at startup, before any other initialization,
	// to configure the plugin's logger. Each plugin owns its own logger
	// package, so the SDK delegates this step.
	InitLogger func()

	// PreConfigInit, if set, runs after config files are resolved but before
	// LoadConfig. Used by plugins that need to validate or fix-up paths
	// referenced in their INI files (e.g. storage paths).
	PreConfigInit func(configFiles []string)

	// Build is called after the session, worker pool, context manager and
	// websocket client have all been initialized. It receives the host
	// resources and returns the Run function that the SDK will spawn in a
	// goroutine, plus an optional Cleanup that runs before exit/restart.
	//
	// The websocket client's lifecycle (Close, ShutDownChan, RestartChan)
	// is owned by the SDK; plugins should not call Close on it themselves.
	//
	// The provided ctx is the plugin's lifecycle context: it is cancelled on
	// shutdown or restart. Long-running goroutines started by Build should
	// honor it.
	Build func(ctx context.Context, host Host) (*BuildResult, error)
}

// Host is the bundle of host-managed resources passed to Plugin.Build. The
// websocket client is fully constructed and ready for the plugin to wire
// into its domain types. The worker pool and context manager that back the
// websocket client are owned by the SDK and intentionally not exposed.
type Host struct {
	Session  *scheduler.Session
	WSClient *runner.WebsocketClient
}

// BuildResult is what Plugin.Build returns to the SDK.
type BuildResult struct {
	// Run is invoked in a goroutine by the SDK. Typically this is the
	// plugin client's RunForever method.
	Run func(ctx context.Context)

	// Cleanup, if non-nil, runs once before the process exits or restarts.
	// It is called after the websocket client is closed but before the pool
	// and context manager are shut down.
	Cleanup func()
}

// NewRootCmd returns a Cobra command that runs the plugin and exposes the
// shared `setup` subcommand. The returned command is suitable for use as the
// plugin binary's root command. NewRootCmd panics if p is nil or fails
// validation, so misconfigured plugins fail at process start rather than at
// first run.
func NewRootCmd(p *Plugin) *cobra.Command {
	if p == nil {
		panic("plugin: nil Plugin")
	}
	if err := p.validate(); err != nil {
		panic(err)
	}
	cmd := &cobra.Command{
		Use:   p.Name,
		Short: fmt.Sprintf("%s agent", p.Name),
		Run: func(cmd *cobra.Command, args []string) {
			p.Run()
		},
	}
	setup.SetConfigPaths(p.Name)
	cmd.AddCommand(setup.SetupCmd)
	return cmd
}

// Run executes the plugin's full lifecycle: signal setup, logger / pidfile /
// config / session initialization, the version handshake, websocket startup,
// and graceful shutdown or in-place restart on the corresponding signals.
//
// Run blocks until the agent stops. On a Restart signal it execs the current
// binary in place and does not return.
func (p *Plugin) Run() {
	switch code := p.run(); code {
	case 0:
		return
	case exitRestart:
		// All deferred cleanups in run have completed; exec the new image.
		p.restartAgent()
		os.Exit(1) // only reached if syscall.Exec fails
	default:
		os.Exit(code)
	}
}

// run drives the plugin lifecycle and returns an exit code (or exitRestart
// to indicate the caller should exec the binary). Using a return value
// instead of os.Exit lets deferred cleanups—pidfile removal, pool shutdown,
// context manager shutdown—run on every exit path.
func (p *Plugin) run() int {
	if err := p.validate(); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err.Error())
		return 1
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigChan)
	go func() {
		select {
		case <-sigChan:
			cancel()
		case <-ctx.Done():
		}
	}()

	if p.InitLogger != nil {
		p.InitLogger()
	}
	utils.InitPlatform()

	pidFilePath, err := pidfile.WritePID(pidfile.FilePath(p.Name))
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "Failed to create PID file.", err.Error())
		return 1
	}

	// Single shutdown closure so the order matches the original per-plugin
	// behavior: ws.Close first (stops incoming reads), then plugin Cleanup,
	// then pool drain, then context manager, then pidfile removal. The
	// captured pointers are nil until the corresponding step succeeds, so
	// the closure is safe to register early.
	var (
		wsClient   *runner.WebsocketClient
		ctxManager *agent.ContextManager
		workerPool *pool.Pool
		buildRes   *BuildResult
	)
	defer func() {
		if wsClient != nil {
			wsClient.Close()
		}
		if buildRes != nil && buildRes.Cleanup != nil {
			buildRes.Cleanup()
		}
		if workerPool != nil {
			if err := workerPool.Shutdown(shutdownTimeout); err != nil {
				log.Warn().Err(err).Msg("Worker pool shutdown timed out.")
			}
		}
		if ctxManager != nil {
			ctxManager.Shutdown()
		}
		log.Debug().Msg("Bye.")
		_ = os.Remove(pidFilePath)
	}()

	log.Info().Msgf("Starting %s... (version: %s)", p.Name, p.Version)

	configFiles := config.Files(p.Name)
	if p.PreConfigInit != nil {
		p.PreConfigInit(configFiles)
	}
	settings := config.LoadConfig(configFiles, p.WSPath, p.ControlWSPath)
	config.InitSettings(settings)

	session := scheduler.InitSession()
	if !p.checkSession(ctx, session) {
		return 1
	}

	ctxManager = agent.NewContextManager()
	workerPool = pool.NewPool(
		config.GlobalSettings.PoolMaxWorkers,
		config.GlobalSettings.PoolQueueSize,
	)
	wsClient = runner.NewWebsocketClient(session, ctxManager, workerPool)

	host := Host{Session: session, WSClient: wsClient}

	log.Info().Msgf("%s initialized and running.", p.Name)

	buildRes, err = p.Build(ctx, host)
	if err != nil {
		log.Error().Err(err).Msg("Plugin build failed.")
		return 1
	}
	if buildRes == nil || buildRes.Run == nil {
		log.Error().Msg("Plugin returned an invalid BuildResult.")
		return 1
	}

	go buildRes.Run(ctx)

	select {
	case <-ctx.Done():
		log.Info().Msg("Received termination signal. Shutting down...")
		return 0
	case <-wsClient.ShutDownChan:
		log.Info().Msg("Shutdown command received. Shutting down...")
		cancel()
		return 0
	case <-wsClient.RestartChan:
		log.Info().Msg("Restart command received. Restarting...")
		cancel()
		return exitRestart
	}
}

func (p *Plugin) validate() error {
	switch {
	case p.Name == "":
		return fmt.Errorf("plugin: Name is required")
	case p.Version == "":
		return fmt.Errorf("plugin: Version is required")
	case p.WSPath == "":
		return fmt.Errorf("plugin: WSPath is required")
	case p.CheckServerURL == "":
		return fmt.Errorf("plugin: CheckServerURL is required")
	case p.Build == nil:
		return fmt.Errorf("plugin: Build is required")
	}
	return nil
}

// checkSession performs the initial version handshake against the server.
// It retries with exponential backoff bounded by the scheduler limits and
// returns false if it cannot reach the server within MaxRetryTimeout, so
// the caller can return an error code through deferred cleanup.
func (p *Plugin) checkSession(ctx context.Context, session *scheduler.Session) bool {
	log.Debug().Msg("Checking current session...")
	timeout := time.Duration(0)
	ctxWithTimeout, cancel := context.WithTimeout(ctx, scheduler.MaxRetryTimeout)
	defer cancel()

	for {
		select {
		case <-ctxWithTimeout.Done():
			log.Error().Msg("Session check cancelled or timed out.")
			return false
		case <-time.After(timeout):
			body := map[string]string{"version": p.Version}

			_, statusCode, err := session.Patch(p.CheckServerURL, body, 5)
			if err != nil || (statusCode != http.StatusOK && statusCode != http.StatusCreated) {
				// Compute the next backoff before logging so the message
				// reflects the actual delay (the previous version logged the
				// stale value, which started at 0s on the first failure).
				next := timeout
				if next == 0 {
					next = config.MinConnectInterval
				}
				next *= 2
				if next > config.MaxConnectInterval {
					next = config.MaxConnectInterval
				}
				log.Debug().Err(err).Msgf(
					"Failed to connect to %s, will try again in %ds",
					config.GlobalSettings.ServerURL, int(next.Seconds()),
				)
				timeout = next
				continue
			}
			return true
		}
	}
}

func (p *Plugin) restartAgent() {
	executable, err := os.Executable()
	if err != nil {
		log.Error().Err(err).Msgf("Failed to restart the %s.", p.Name)
		return
	}
	if err := syscall.Exec(executable, os.Args, os.Environ()); err != nil {
		log.Error().Err(err).Msgf("Failed to restart the %s.", p.Name)
	}
}
