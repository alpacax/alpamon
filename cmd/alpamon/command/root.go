package command

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/alpacax/alpamon/cmd/alpamon/command/ftp"
	"github.com/alpacax/alpamon/cmd/alpamon/command/setup"
	"github.com/alpacax/alpamon/internal/pool"
	"github.com/alpacax/alpamon/pkg/agent"
	"github.com/alpacax/alpamon/pkg/collector"
	"github.com/alpacax/alpamon/pkg/config"
	"github.com/alpacax/alpamon/pkg/db"
	"github.com/alpacax/alpamon/pkg/logger"
	"github.com/alpacax/alpamon/pkg/pidfile"
	"github.com/alpacax/alpamon/pkg/runner"
	"github.com/alpacax/alpamon/pkg/scheduler"
	"github.com/alpacax/alpamon/pkg/utils"
	"github.com/alpacax/alpamon/pkg/version"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"gopkg.in/natefinch/lumberjack.v2"
)

const (
	name   = "alpamon"
	wsPath = "/ws/servers/backhaul/"
)

var RootCmd = &cobra.Command{
	Use:   "alpamon",
	Short: "Secure Server Agent for Alpacon",
	Run: func(cmd *cobra.Command, args []string) {
		runAgent()
	},
}

func init() {
	setup.SetConfigPaths(name)
	RootCmd.AddCommand(setup.SetupCmd, ftp.FtpCmd)
}

func runAgent() {
	// Create global context manager for the entire application
	ctxManager := agent.NewContextManager()
	ctx := ctxManager.Root()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		ctxManager.Shutdown()
	}()

	// Logger
	logRotate := logger.InitLogger()

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
	settings := config.LoadConfig(config.Files(name), wsPath)
	config.InitSettings(settings)

	// Create global worker pool for the entire application using config settings
	workerPool := pool.NewPool(settings.PoolMaxWorkers, settings.PoolQueueSize)
	log.Info().Msgf("Initialized global worker pool with %d workers and queue capacity %d",
		workerPool.MaxWorkers(), workerPool.QueueCapacity())

	// Session
	session := scheduler.InitSession()
	commissioned := session.CheckSession(ctx)

	// Reporter - pass context manager for centralized context management
	scheduler.StartReporters(session, ctxManager)

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
	go wsClient.RunForever(ctx)

	for {
		select {
		case <-ctx.Done():
			log.Info().Msg("Received termination signal. Shutting down...")
			gracefulShutdown(metricCollector, wsClient, workerPool, logRotate, logServer, pidFilePath)
			return
		case <-wsClient.ShutDownChan:
			log.Info().Msg("Shutdown command received. Shutting down...")
			ctxManager.Shutdown()
			gracefulShutdown(metricCollector, wsClient, workerPool, logRotate, logServer, pidFilePath)
			return
		case <-wsClient.RestartChan:
			log.Info().Msg("Restart command received. Restarting...")
			ctxManager.Shutdown()
			gracefulShutdown(metricCollector, wsClient, workerPool, logRotate, logServer, pidFilePath)
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

func restartAgent() {
	executable, err := os.Executable()
	if err != nil {
		log.Error().Err(err).Msgf("Failed to restart the %s.", name)
		return
	}

	err = syscall.Exec(executable, os.Args, os.Environ())
	if err != nil {
		log.Error().Err(err).Msgf("Failed to restart the %s.", name)
	}
}

func gracefulShutdown(collector *collector.Collector, wsClient *runner.WebsocketClient, workerPool *pool.Pool, logRotate *lumberjack.Logger, logServer *logger.LogServer, pidPath string) {
	if collector != nil {
		collector.Stop()
	}
	if wsClient != nil {
		wsClient.Close()
	}
	// Shutdown the global worker pool
	if workerPool != nil {
		log.Info().Msg("Shutting down global worker pool...")
		if err := workerPool.Shutdown(10 * time.Second); err != nil {
			log.Error().Err(err).Msg("Failed to shutdown worker pool gracefully")
		}
	}
	if logServer != nil {
		logServer.Stop()
	}

	log.Debug().Msg("Bye.")

	if logRotate != nil {
		_ = logRotate.Close()
	}
	_ = os.Remove(pidPath)
}
