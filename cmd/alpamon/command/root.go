package command

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/alpacax/alpamon/v2/cmd/alpamon/command/ftp"
	migratecmd "github.com/alpacax/alpamon/v2/cmd/alpamon/command/migrate"
	"github.com/alpacax/alpamon/v2/cmd/alpamon/command/register"
	"github.com/alpacax/alpamon/v2/cmd/alpamon/command/setup"
	"github.com/alpacax/alpamon/v2/cmd/alpamon/command/tunnel"
	"github.com/alpacax/alpamon/v2/internal/pool"
	"github.com/alpacax/alpamon/v2/pkg/agent"
	"github.com/alpacax/alpamon/v2/pkg/collector"
	"github.com/alpacax/alpamon/v2/pkg/config"
	"github.com/alpacax/alpamon/v2/pkg/db"
	"github.com/alpacax/alpamon/v2/pkg/executor"
	"github.com/alpacax/alpamon/v2/pkg/logger"
	"github.com/alpacax/alpamon/v2/pkg/migrate"
	"github.com/alpacax/alpamon/v2/pkg/pidfile"
	"github.com/alpacax/alpamon/v2/pkg/runner"
	"github.com/alpacax/alpamon/v2/pkg/scheduler"
	"github.com/alpacax/alpamon/v2/pkg/updater"
	"github.com/alpacax/alpamon/v2/pkg/utils"
	"github.com/alpacax/alpamon/v2/pkg/version"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

const (
	name          = "alpamon"
	wsPath        = "/ws/servers/backhaul/"
	controlWsPath = "/ws/servers/control/"
)

var RootCmd = &cobra.Command{
	Use:   "alpamon",
	Short: "Alpacon agent: outbound-only server connection for AI-native PAM",
	Long: `Alpamon is the open-source server agent for Alpacon, the AI-native PAM
control plane. Installed on each managed server, alpamon establishes an
outbound-only connection to Alpacon (no inbound ports, no firewall changes)
and enforces server-side decisions locally: command execution, file
transfer, sudo verification (via alpamon-pam), and remote management.

Typical usage:

  alpamon register --url https://<workspace> --token <TOKEN>   # one-time setup
  systemctl status alpamon                                     # service state
  alpamon migrate --to-workspace <new-workspace>               # workspace move

After 'register' completes, the agent runs as a system service and operates
on its own. Other subcommands (ftp, setup, tunnel-daemon) are internal
workers spawned by the agent itself and are not meant to be invoked by users.

Run 'alpamon <command> --help' for details. See https://alpacon.io for the
control plane and https://github.com/alpacax/alpacon-cli for the CLI.`,
	Version: version.Version,
	Run: func(cmd *cobra.Command, args []string) {
		// When launched by the Windows Service Control Manager, run
		// under the svc dispatcher instead of as a plain console app.
		// No-op / always false on Unix.
		if runningAsWindowsService() {
			runService()
			return
		}
		runAgent(nil)
	},
}

func init() {
	setup.SetConfigPaths(name)
	RootCmd.AddCommand(setup.SetupCmd, ftp.FtpCmd, tunnel.TunnelDaemonCmd, register.RegisterCmd, register.UnregisterCmd, migratecmd.Cmd)
	// Emit just the version string (no "alpamon version ..." prefix) so
	// shell one-liners like `alpamon --version` are easy to parse.
	RootCmd.SetVersionTemplate("{{.Version}}\n")
}

// runAgent is the core agent loop. When ready is non-nil, it is
// closed as soon as the shutdown hook is installed — the Windows
// Service handler uses this to delay reporting Running until a
// Stop request can actually be honored.
func runAgent(ready chan<- struct{}) {
	// Create global context manager for the entire application
	ctxManager := agent.NewContextManager()
	ctx := ctxManager.Root()

	setupSignalHandler(ctxManager)
	setShutdownFunc(ctxManager.Shutdown)
	defer setShutdownFunc(nil)
	if ready != nil {
		close(ready)
	}

	// Logger
	logger.InitLogger()

	// On Windows, clean up any ".old" binary left behind by a prior
	// self-update before the new process takes over. No-op on Unix.
	updater.CleanupStaleOld()

	// platform
	utils.InitPlatform()

	// Pid
	pidFilePath, err := pidfile.WritePID(pidfile.FilePath(name))
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "Failed to create PID file", err.Error())
		os.Exit(1)
	}

	log.Info().Msgf("Starting alpamon... (version: %s)", version.Version)

	// Config & Settings
	settings := config.LoadConfig(config.Files(name), wsPath, controlWsPath)
	config.InitSettings(settings)

	// Create global worker pool for the entire application using config settings
	workerPool := pool.NewPool(settings.PoolMaxWorkers, settings.PoolQueueSize)
	log.Info().Msgf("Initialized global worker pool with %d workers and queue capacity %d",
		workerPool.MaxWorkers(), workerPool.QueueCapacity())

	// Session
	session := scheduler.InitSession()
	commissioned := session.CheckSession(ctx)

	// Reporter - pass context manager for centralized context management
	reporters := scheduler.StartReporters(session, ctxManager)

	// Log server - pass worker pool and context manager for connection handling
	logServer := logger.NewLogServer(workerPool, ctxManager)
	if logServer != nil {
		go logServer.StartLogServer()
	}

	log.Info().Msgf("%s initialized and running.", name)

	// Commit - pass context manager for coordinated lifecycle management
	runner.CommitAsync(session, commissioned, ctxManager)

	// DB
	client := db.InitDB()

	// Collector - pass context manager for centralized context management
	metricCollector := collector.InitCollector(session, client, ctxManager)
	if metricCollector != nil {
		metricCollector.Start()
	}

	// Websocket Client - pass context manager and worker pool for centralized management
	wsClient := runner.NewWebsocketClient(session, ctxManager, workerPool)

	// Workspace migration: if a previous `alpamon migrate` left a pending
	// marker, arm the watchdog and register the connect-success hook so
	// the marker is cleared once we authenticate against the new
	// workspace. See pkg/migrate for the full state machine.
	wirePendingMigration(ctx, wsClient, settings)

	// Initialize dispatcher system with callbacks
	dispatcher, err := executor.InitDispatcher(
		workerPool,
		ctxManager,
		session,
		wsClient,
		executor.SystemInfoCallbacks{
			CommitFunc: runner.CommitSystemInfo,
			SyncFunc:   runner.SyncSystemInfo,
		},
	)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to initialize dispatcher system")
	}

	wsClient.SetDispatcher(dispatcher)
	log.Info().Msg("Dispatcher system initialized successfully")

	go wsClient.RunForever(ctx)

	// Control Client (Control - sudo approval)
	controlClient := runner.NewControlClient()
	go controlClient.RunForever(ctx)

	// Auth Manager for sudo approval workflow
	authManager := runner.GetAuthManager(controlClient, session)
	go authManager.Start(ctx)

	for {
		select {
		case <-ctx.Done():
			log.Info().Msg("Received termination signal. Shutting down...")
			gracefulShutdown(metricCollector, wsClient, controlClient, authManager, workerPool, logServer, reporters, pidFilePath)
			return
		case <-wsClient.ShutDownChan:
			log.Info().Msg("Shutdown command received. Shutting down...")
			ctxManager.Shutdown()
			gracefulShutdown(metricCollector, wsClient, controlClient, authManager, workerPool, logServer, reporters, pidFilePath)
			return
		case <-wsClient.RestartChan:
			log.Info().Msg("Restart command received. Restarting...")
			ctxManager.Shutdown()
			gracefulShutdown(metricCollector, wsClient, controlClient, authManager, workerPool, logServer, reporters, pidFilePath)
			restartAgent()
			return
		case <-wsClient.CollectorRestartChan:
			log.Info().Msg("Collector restart command received. Restarting Collector...")
			metricCollector.Stop()
			metricCollector = collector.InitCollector(session, client, ctxManager)
			metricCollector.Start()
		}
	}
}

func gracefulShutdown(collector *collector.Collector, wsClient *runner.WebsocketClient, controlClient *runner.ControlClient, authManager *runner.AuthManager, workerPool *pool.Pool, logServer *logger.LogServer, reporters *scheduler.ReporterManager, pidPath string) {
	runner.CloseAllActiveTunnels()
	runner.CloseAllActiveFtpWorkers()

	if collector != nil {
		collector.Stop()
	}
	if wsClient != nil {
		wsClient.Close()
	}
	if controlClient != nil {
		controlClient.Close()
	}
	if authManager != nil {
		authManager.Stop()
	}
	// Shutdown reporters before worker pool
	if reporters != nil {
		if err := reporters.Shutdown(1 * time.Second); err != nil {
			log.Error().Err(err).Msg("Failed to shutdown reporters gracefully")
		}
	}
	// Shutdown the global worker pool
	if workerPool != nil {
		log.Info().Msg("Shutting down global worker pool...")
		if err := workerPool.Shutdown(1 * time.Second); err != nil {
			log.Error().Err(err).Msg("Failed to shutdown worker pool gracefully")
		}
	}
	if logServer != nil {
		logServer.Stop()
	}

	log.Debug().Msg("Bye.")

	_ = os.Remove(pidPath)
}

// wirePendingMigration inspects the migration marker on startup. When a
// migration is in flight, it registers a Confirm hook via
// SetOnAuthenticated (which fires only after the first successful
// ReadMessage on a fresh connection, i.e. genuine traffic from the target
// workspace) and arms a watchdog that rolls back to the previous
// workspace if the new one never accepts the agent.
//
// Confirm is guarded by sync.Once because SetOnAuthenticated fires on
// every reconnect, not just the first; we want to clear the marker
// exactly once.
func wirePendingMigration(ctx context.Context, wsClient *runner.WebsocketClient, settings config.Settings) {
	// Migration relies on systemd-run for self-restart. On platforms
	// without systemd (Windows, container, dev macOS) the watchdog has no
	// way to recover the agent from a failed migration; refuse to arm it
	// rather than leave the operator with a half-wired safety net.
	if !utils.HasSystemd() {
		return
	}

	state, err := migrate.LoadPending()
	if err != nil {
		log.Warn().Err(err).Msg("Failed to load migration marker; continuing without migration watchdog.")
		return
	}
	if state == nil {
		return
	}

	log.Info().
		Str("from", state.OldURL).
		Str("to", state.NewURL).
		Time("started_at", state.StartedAt).
		Time("expires_at", state.ExpiresAt).
		Msg("Detected pending workspace migration.")

	confPath := filepath.Join(utils.ConfigDir(), "alpamon.conf")

	// confirmed gates the rollback callback against a successful connect
	// that races past the watchdog timer. Without this, an unlucky timing
	// could cause Rollback to call the B-side unregister endpoint after
	// the agent has already established a live session with B.
	var confirmed atomic.Bool
	var confirmOnce sync.Once

	cancelWatchdog := migrate.StartWatchdog(ctx, state, func(cur *migrate.PendingState) {
		if confirmed.Load() {
			log.Info().Msg("Watchdog fired but Confirm already happened; standing down.")
			return
		}
		if err := migrate.Rollback(cur, confPath, settings.SSLVerify, settings.CaCert); err != nil {
			log.Error().Err(err).
				Str("marker", migrate.MarkerPath()).
				Str("backup", cur.BackupConfPath).
				Str("conf", confPath).
				Msg("Migration rollback failed; inspect/remove the marker, restore the backup manually, then restart alpamon.")
			return
		}
		// Signal the main loop to run gracefulShutdown. systemd-run's
		// 2-second-delayed `systemctl restart` brings us back up with
		// the restored config and a clean shutdown trail.
		log.Info().Msg("Migration rolled back; requesting graceful shutdown to await systemd restart.")
		wsClient.ShutDown()
	})

	wsClient.SetOnAuthenticated(func() {
		confirmOnce.Do(func() {
			confirmed.Store(true)
			cancelWatchdog()
			migrate.Confirm(state)
		})
	})
}
