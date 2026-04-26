// Package plugin provides a shared host runtime for alpamon plugins.
//
// It encapsulates the boilerplate that every plugin previously duplicated:
// signal handling, pidfile management, config loading, session setup, the
// initial server-side version handshake, and the websocket lifecycle
// (graceful shutdown + in-place restart).
//
// A plugin defines a Plugin value and either calls Plugin.Run directly or
// embeds it under a Cobra root command via NewRootCmd.
package plugin

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/alpacax/alpamon/cmd/alpamon/command/setup"
	"github.com/alpacax/alpamon/internal/pool"
	"github.com/alpacax/alpamon/pkg/agent"
	"github.com/alpacax/alpamon/pkg/config"
	"github.com/alpacax/alpamon/pkg/pidfile"
	"github.com/alpacax/alpamon/pkg/runner"
	"github.com/alpacax/alpamon/pkg/scheduler"
	"github.com/alpacax/alpamon/pkg/utils"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

// shutdownTimeout bounds how long the SDK waits for the worker pool to drain.
const shutdownTimeout = 30 * time.Second

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
	// LoadConfig. Used by plugins that need to validate / fix-up paths
	// referenced in their INI files (e.g. storage paths).
	PreConfigInit func(configFiles []string)

	// Build is called after the session, worker pool, context manager and
	// websocket client have all been initialized. It receives the host
	// resources and returns the Run function that the SDK will spawn in a
	// goroutine, plus an optional Cleanup that runs before exit/restart.
	//
	// The websocket client's lifecycle (Close, ShutDownChan, RestartChan)
	// is owned by the SDK; plugins should not call Close on it themselves.
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
// plugin binary's root command.
func NewRootCmd(p *Plugin) *cobra.Command {
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
	if err := p.validate(); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
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
		os.Exit(1)
	}
	defer func() { _ = os.Remove(pidFilePath) }()

	log.Info().Msgf("Starting %s... (version: %s)", p.Name, p.Version)

	configFiles := config.Files(p.Name)
	if p.PreConfigInit != nil {
		p.PreConfigInit(configFiles)
	}
	settings := config.LoadConfig(configFiles, p.WSPath, p.ControlWSPath)
	config.InitSettings(settings)

	session := scheduler.InitSession()
	p.checkSession(ctx, session)

	ctxManager := agent.NewContextManager()
	workerPool := pool.NewPool(
		config.GlobalSettings.PoolMaxWorkers,
		config.GlobalSettings.PoolQueueSize,
	)
	wsClient := runner.NewWebsocketClient(session, ctxManager, workerPool)

	host := Host{
		Session:  session,
		WSClient: wsClient,
	}

	log.Info().Msgf("%s initialized and running.", p.Name)

	result, err := p.Build(ctx, host)
	if err != nil {
		log.Error().Err(err).Msg("Plugin build failed.")
		os.Exit(1)
	}
	if result == nil || result.Run == nil {
		log.Error().Msg("Plugin returned an invalid BuildResult.")
		os.Exit(1)
	}

	go result.Run(ctx)

	restart := false
	select {
	case <-ctx.Done():
		log.Info().Msg("Received termination signal. Shutting down...")
	case <-wsClient.ShutDownChan:
		log.Info().Msg("Shutdown command received. Shutting down...")
		cancel()
	case <-wsClient.RestartChan:
		log.Info().Msg("Restart command received. Restarting...")
		cancel()
		restart = true
	}

	p.gracefulShutdown(host, result, workerPool, ctxManager, pidFilePath)

	if restart {
		p.restartAgent()
	}
}

func (p *Plugin) validate() error {
	switch {
	case p.Name == "":
		return fmt.Errorf("plugin: Name is required")
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
// exits the process if it cannot reach the server within MaxRetryTimeout.
func (p *Plugin) checkSession(ctx context.Context, session *scheduler.Session) {
	log.Debug().Msg("Checking current session...")
	timeout := time.Duration(0)
	ctxWithTimeout, cancel := context.WithTimeout(ctx, scheduler.MaxRetryTimeout)
	defer cancel()

	for {
		select {
		case <-ctxWithTimeout.Done():
			log.Error().Msg("Session check cancelled or timed out.")
			os.Exit(1)
		case <-time.After(timeout):
			jsonData, _ := json.Marshal(map[string]string{"version": p.Version})

			_, statusCode, err := session.Patch(p.CheckServerURL, jsonData, 5)
			if err != nil || (statusCode != http.StatusOK && statusCode != http.StatusCreated) {
				log.Debug().Err(err).Msgf(
					"Failed to connect to %s, will try again in %ds",
					config.GlobalSettings.ServerURL, int(timeout.Seconds()),
				)
				if timeout == 0 {
					timeout = config.MinConnectInterval
				}
				timeout *= 2
				if timeout > config.MaxConnectInterval {
					timeout = config.MaxConnectInterval
				}
				continue
			}
			return
		}
	}
}

func (p *Plugin) gracefulShutdown(host Host, result *BuildResult, workerPool *pool.Pool, ctxManager *agent.ContextManager, pidPath string) {
	if host.WSClient != nil {
		host.WSClient.Close()
	}
	if result != nil && result.Cleanup != nil {
		result.Cleanup()
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
	_ = os.Remove(pidPath)
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
