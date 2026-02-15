package system

import (
	"context"
	"fmt"
	"time"

	"github.com/alpacax/alpamon/internal/pool"
	"github.com/alpacax/alpamon/pkg/agent"
	"github.com/alpacax/alpamon/pkg/config"
	"github.com/alpacax/alpamon/pkg/executor/handlers/common"
	"github.com/alpacax/alpamon/pkg/utils"
	"github.com/alpacax/alpamon/pkg/version"
	"github.com/rs/zerolog/log"
)

// SystemHandler handles system-level commands like restart, reboot, shutdown, upgrade
type SystemHandler struct {
	*common.BaseHandler
	wsClient   common.WSClient
	ctxManager *agent.ContextManager
	pool       *pool.Pool
}

// NewSystemHandler creates a new system handler
func NewSystemHandler(cmdExecutor common.CommandExecutor, wsClient common.WSClient, ctxManager *agent.ContextManager, pool *pool.Pool) *SystemHandler {
	h := &SystemHandler{
		BaseHandler: common.NewBaseHandler(
			common.System,
			[]common.CommandType{
				common.Upgrade,
				common.Restart,
				common.Quit,
				common.Reboot,
				common.Shutdown,
				common.Update,
				common.ByeBye,
			},
			cmdExecutor,
		),
		wsClient:   wsClient,
		ctxManager: ctxManager,
		pool:       pool,
	}
	return h
}

// Execute runs the system command
func (h *SystemHandler) Execute(ctx context.Context, cmd string, args *common.CommandArgs) (int, string, error) {
	switch cmd {
	case common.Upgrade.String():
		return h.handleUpgrade(ctx)
	case common.Restart.String():
		return h.handleRestart(args)
	case common.Quit.String():
		return h.handleQuit()
	case common.ByeBye.String():
		return h.handleUninstall()
	case common.Reboot.String():
		return h.handleReboot()
	case common.Shutdown.String():
		return h.handleShutdown()
	case common.Update.String():
		return h.handleSystemUpdate(ctx)
	default:
		return 1, "", fmt.Errorf("unknown system command: %s", cmd)
	}
}

// Validate checks if the arguments are valid for the command
func (h *SystemHandler) Validate(cmd string, args *common.CommandArgs) error {
	// Most system commands don't require arguments
	return nil
}

// handleUpgrade handles the upgrade command
func (h *SystemHandler) handleUpgrade(ctx context.Context) (int, string, error) {
	latestVersion := utils.GetLatestVersion()

	if version.Version == latestVersion {
		return 0, fmt.Sprintf("Alpamon is already up-to-date (version: %s)", version.Version), nil
	}

	var cmd string
	switch utils.PlatformLike {
	case "debian":
		cmd = "apt-get update -y && apt-get install --only-upgrade alpamon -y"
	case "rhel":
		cmd = "yum update -y alpamon"
	default:
		return 1, fmt.Sprintf("Platform '%s' not supported.", utils.PlatformLike), nil
	}

	log.Debug().Msgf("Upgrading alpamon from %s to %s using command: '%s'...", version.Version, latestVersion, cmd)

	exitCode, output, err := h.Executor.RunAsUser(ctx, "root", "sh", "-c", cmd)
	return exitCode, output, err
}

// handleRestart handles the restart command
func (h *SystemHandler) handleRestart(args *common.CommandArgs) (int, string, error) {
	target := args.Target
	if target == "" {
		target = "alpamon"
	}
	message := "Alpamon will restart in 1 second."

	switch target {
	case "collector":
		log.Info().Msg("Restart collector.")
		h.wsClient.RestartCollector()
		message = "Collector will be restarted."
	default:
		// Submit to worker pool for managed execution
		poolCtx, cancel := h.ctxManager.NewContext(2 * time.Second)
		submitted := false
		defer func() {
			if !submitted {
				cancel()
			}
		}()

		err := h.pool.Submit(poolCtx, func() error {
			defer cancel()
			time.Sleep(1 * time.Second)
			h.wsClient.Restart()
			return nil
		})
		if err != nil {
			log.Error().Err(err).Msg("Failed to submit restart task to pool")
		} else {
			submitted = true
		}
	}

	return 0, message, nil
}

// handleQuit handles the quit command
func (h *SystemHandler) handleQuit() (int, string, error) {
	// Submit to worker pool for managed execution
	poolCtx, cancel := h.ctxManager.NewContext(2 * time.Second)
	submitted := false
	defer func() {
		if !submitted {
			cancel()
		}
	}()

	err := h.pool.Submit(poolCtx, func() error {
		defer cancel()
		time.Sleep(1 * time.Second)
		h.wsClient.ShutDown()
		return nil
	})
	if err != nil {
		log.Error().Err(err).Msg("Failed to submit quit task to pool")
	} else {
		submitted = true
	}
	return 0, "Alpamon will shutdown in 1 second.", nil
}

// handleUninstall handles the byebye (uninstall) command
func (h *SystemHandler) handleUninstall() (int, string, error) {
	log.Info().Msg("Uninstall request received.")

	// Execute uninstall after 1 second to ensure response is sent
	time.AfterFunc(1*time.Second, func() {
		h.executeUninstall()
	})

	return 0, "Starting uninstall process...", nil
}

// executeUninstall performs the actual uninstall
func (h *SystemHandler) executeUninstall() {
	var cmd string

	if utils.PlatformLike == "debian" {
		// Use purge to remove package and config files
		cmd = "apt-get purge alpamon -y && apt-get autoremove -y"
	} else if utils.PlatformLike == "rhel" {
		// Remove package using yum
		cmd = "yum remove alpamon -y"
	} else if utils.PlatformLike == "darwin" {
		// For macOS development environment, just shutdown
		log.Warn().Msgf("Platform '%s' does not support full uninstall. Shutting down instead.", utils.PlatformLike)
		h.wsClient.ShutDown()
		return
	} else {
		log.Error().Msgf("Platform '%s' not supported for uninstall.", utils.PlatformLike)
		h.wsClient.ShutDown()
		return
	}

	// Build the complete uninstall command that includes:
	// 1. Package removal
	// 2. Cleanup of transient systemd units created by this operation
	uninstallCmd := fmt.Sprintf("%s; systemctl reset-failed alpamon-uninstall.service 2>/dev/null || true; systemctl reset-failed alpamon-uninstall.timer 2>/dev/null || true", cmd)

	// This ensures the uninstall continues even after the current process terminates
	// The service will start 5 seconds after being scheduled
	// --collect: Automatically clean up transient units after they complete (systemd 236+)
	scheduleCmdArgs := []string{
		"systemd-run",
		"--collect",
		"--uid=0",
		"--gid=0",
		"--unit=alpamon-uninstall",
		"--timer-property=OnActiveSec=5",
		"--timer-property=AccuracySec=1s",
		"--description=Alpamon Uninstall Service",
		"/bin/sh", "-c", uninstallCmd,
	}

	ctx := context.Background()
	exitCode, output, _ := h.Executor.RunWithTimeout(ctx, 30*time.Second, scheduleCmdArgs[0], scheduleCmdArgs[1:]...)

	if exitCode != 0 {
		log.Error().Msgf("Failed to schedule uninstall: %s", output)
		// Fallback to direct execution
		_, _, _ = h.Executor.RunAsUser(ctx, "root", "sh", "-c", cmd)
	}

	// Shutdown the process after scheduling
	h.wsClient.ShutDown()
}

// handleReboot handles the reboot command
func (h *SystemHandler) handleReboot() (int, string, error) {
	log.Info().Msg("Reboot request received.")

	// Submit to worker pool for managed execution
	poolCtx, cancel := h.ctxManager.NewContext(time.Duration(config.GlobalSettings.PoolDefaultTimeout) * time.Second)
	submitted := false
	defer func() {
		if !submitted {
			cancel()
		}
	}()

	err := h.pool.Submit(poolCtx, func() error {
		defer cancel()
		time.Sleep(1 * time.Second)
		_, _, _ = h.Executor.RunAsUser(poolCtx, "root", "reboot")
		return nil
	})
	if err != nil {
		log.Error().Err(err).Msg("Failed to submit reboot task to pool")
	} else {
		submitted = true
	}

	return 0, "Server will reboot in 1 second", nil
}

// handleShutdown handles the shutdown command
func (h *SystemHandler) handleShutdown() (int, string, error) {
	log.Info().Msg("Shutdown request received.")

	// Submit to worker pool for managed execution
	poolCtx, cancel := h.ctxManager.NewContext(time.Duration(config.GlobalSettings.PoolDefaultTimeout) * time.Second)
	submitted := false
	defer func() {
		if !submitted {
			cancel()
		}
	}()

	err := h.pool.Submit(poolCtx, func() error {
		defer cancel()
		time.Sleep(1 * time.Second)
		_, _, _ = h.Executor.RunAsUser(poolCtx, "root", "shutdown", "now")
		return nil
	})
	if err != nil {
		log.Error().Err(err).Msg("Failed to submit shutdown task to pool")
	} else {
		submitted = true
	}

	return 0, "Server will shutdown in 1 second", nil
}

// handleSystemUpdate handles the update command (system-wide updates)
func (h *SystemHandler) handleSystemUpdate(ctx context.Context) (int, string, error) {
	log.Info().Msg("Upgrade system requested.")

	var cmd string
	if utils.PlatformLike == "debian" {
		cmd = "apt-get update && apt-get upgrade -y && apt-get autoremove -y"
	} else if utils.PlatformLike == "rhel" {
		cmd = "yum update -y"
	} else if utils.PlatformLike == "darwin" {
		cmd = "brew upgrade"
	} else {
		return 1, fmt.Sprintf("Platform '%s' not supported.", utils.PlatformLike), nil
	}

	exitCode, output, err := h.Executor.RunAsUser(ctx, "root", "sh", "-c", cmd)
	return exitCode, output, err
}
