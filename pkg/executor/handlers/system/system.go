package system

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/alpacax/alpamon/internal/pool"
	"github.com/alpacax/alpamon/pkg/agent"
	"github.com/alpacax/alpamon/pkg/executor/handlers/common"
	"github.com/alpacax/alpamon/pkg/utils"
	"github.com/alpacax/alpamon/pkg/version"
	"github.com/rs/zerolog/log"
)

// SystemHandler handles system-level commands like restart, reboot, shutdown, upgrade
type SystemHandler struct {
	*common.BaseHandler
	wsClient        common.WSClient
	ctxManager      *agent.ContextManager
	pool            *pool.Pool
	versionResolver common.VersionResolver
}

// NewSystemHandler creates a new system handler.
// versionResolver must not be nil; pass utils.NewDefaultVersionResolver() for production.
func NewSystemHandler(cmdExecutor common.CommandExecutor, wsClient common.WSClient, ctxManager *agent.ContextManager, pool *pool.Pool, versionResolver common.VersionResolver) *SystemHandler {
	if versionResolver == nil {
		panic("system: versionResolver must not be nil")
	}
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
		wsClient:        wsClient,
		ctxManager:      ctxManager,
		pool:            pool,
		versionResolver: versionResolver,
	}
	return h
}

// Execute runs the system command
func (h *SystemHandler) Execute(ctx context.Context, cmd string, args *common.CommandArgs) (int, string, error) {
	switch cmd {
	case common.Upgrade.String():
		return h.withTimeout(ctx, common.UpgradeTimeout, h.handleUpgrade)
	case common.Restart.String():
		ctx, cancel := common.WithHandlerTimeout(ctx, common.SystemCmdTimeout)
		defer cancel()
		exitCode, output, err := h.handleRestart(args)
		if err != nil && common.IsTimeout(ctx) {
			return common.TimeoutError(common.SystemCmdTimeout)
		}
		return exitCode, output, err
	case common.Quit.String():
		ctx, cancel := common.WithHandlerTimeout(ctx, common.SystemCmdTimeout)
		defer cancel()
		exitCode, output, err := h.handleQuit()
		if err != nil && common.IsTimeout(ctx) {
			return common.TimeoutError(common.SystemCmdTimeout)
		}
		return exitCode, output, err
	case common.ByeBye.String():
		ctx, cancel := common.WithHandlerTimeout(ctx, common.SystemCmdTimeout)
		defer cancel()
		exitCode, output, err := h.handleUninstall()
		if err != nil && common.IsTimeout(ctx) {
			return common.TimeoutError(common.SystemCmdTimeout)
		}
		return exitCode, output, err
	case common.Reboot.String():
		ctx, cancel := common.WithHandlerTimeout(ctx, common.SystemCmdTimeout)
		defer cancel()
		exitCode, output, err := h.handleReboot()
		if err != nil && common.IsTimeout(ctx) {
			return common.TimeoutError(common.SystemCmdTimeout)
		}
		return exitCode, output, err
	case common.Shutdown.String():
		ctx, cancel := common.WithHandlerTimeout(ctx, common.SystemCmdTimeout)
		defer cancel()
		exitCode, output, err := h.handleShutdown()
		if err != nil && common.IsTimeout(ctx) {
			return common.TimeoutError(common.SystemCmdTimeout)
		}
		return exitCode, output, err
	case common.Update.String():
		return h.withTimeout(ctx, common.UpgradeTimeout, h.handleSystemUpdate)
	default:
		return 1, "", fmt.Errorf("unknown system command: %s", cmd)
	}
}

// withTimeout wraps a context-dependent handler method with a timeout.
func (h *SystemHandler) withTimeout(ctx context.Context, timeout time.Duration, fn func(context.Context) (int, string, error)) (int, string, error) {
	ctx, cancel := common.WithHandlerTimeout(ctx, timeout)
	defer cancel()
	exitCode, output, err := fn(ctx)
	if err != nil && common.IsTimeout(ctx) {
		return common.TimeoutError(timeout)
	}
	return exitCode, output, err
}

// Validate checks if the arguments are valid for the command
func (h *SystemHandler) Validate(cmd string, args *common.CommandArgs) error {
	// Most system commands don't require arguments
	return nil
}

// handleUpgrade handles the upgrade command.
// It checks alpamon and alpamon-pam versions independently and upgrades only
// the packages that need it. This prevents skipping a pam-only upgrade when
// alpamon is already at the latest version.
func (h *SystemHandler) handleUpgrade(ctx context.Context) (int, string, error) {
	latestVersion := h.versionResolver.GetLatestVersion()
	if latestVersion == "" {
		return 1, "Failed to retrieve the latest Alpamon version from GitHub.",
			errors.New("failed to retrieve the latest Alpamon version from GitHub")
	}

	needAlpamon := version.Version != latestVersion

	currentPamVersion := h.versionResolver.GetPamVersion()
	needPam := currentPamVersion != "" && currentPamVersion != latestVersion

	if !needAlpamon && !needPam {
		pamDisplay := currentPamVersion
		if pamDisplay == "" {
			pamDisplay = "not installed"
		}
		return 0, fmt.Sprintf("Already up-to-date (alpamon: %s, pam: %s)", version.Version, pamDisplay), nil
	}

	var packages []string
	if needAlpamon {
		packages = append(packages, "alpamon")
	}
	if needPam {
		packages = append(packages, "alpamon-pam")
	}
	pkgList := strings.Join(packages, " ")

	var cmd string
	switch utils.PlatformLike {
	case "debian":
		cmd = fmt.Sprintf("apt-get update -y -o Acquire::Retries=3 && apt-get install --only-upgrade %s -y -o Acquire::Retries=3", pkgList)
	case "rhel":
		cmd = fmt.Sprintf("yum update -y %s", pkgList)
	case "darwin":
		return 1, "Automatic upgrade is not supported on macOS. Please download the latest binary from the release channel and replace /usr/local/bin/alpamon manually.", nil
	default:
		return 1, fmt.Sprintf("Platform '%s' not supported.", utils.PlatformLike), nil
	}

	log.Debug().Msgf("Upgrading %s...", pkgList)
	exitCode, output, err := h.Executor.RunAsUser(ctx, "root", "sh", "-c", cmd)
	if exitCode == 0 && needPam {
		h.versionResolver.InvalidatePamCache()
	}
	return exitCode, output, err
}

// handleRestart handles the restart command.
// This is a fire-and-forget command: the response is returned immediately and
// the actual restart runs asynchronously via the pool with its own context
// from ctxManager. The handler-level timeout in Execute() covers the synchronous
// dispatch; the pool task manages its own lifecycle via ctxManager.NewContext().
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

// handleQuit handles the quit command.
// See handleRestart for the fire-and-forget pattern.
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

// handleUninstall handles the byebye (uninstall) command.
// See handleRestart for the fire-and-forget pattern. executeUninstall uses
// context.Background() intentionally because the uninstall must complete even
// after the agent's own context tree is shut down.
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

	switch utils.PlatformLike {
	case "debian":
		// Use purge to remove package and config files
		cmd = "apt-get purge alpamon -y && apt-get autoremove -y"
	case "rhel":
		// Remove package using yum
		cmd = "yum remove alpamon -y"
	case "darwin":
		// For macOS development environment, just shutdown
		log.Warn().Msgf("Platform '%s' does not support full uninstall. Shutting down instead.", utils.PlatformLike)
		h.wsClient.ShutDown()
		return
	default:
		log.Error().Msgf("Platform '%s' not supported for uninstall.", utils.PlatformLike)
		h.wsClient.ShutDown()
		return
	}

	ctx := context.Background()

	if utils.HasSystemd() {
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

		exitCode, output, _ := h.Executor.RunWithTimeout(ctx, 30*time.Second, scheduleCmdArgs[0], scheduleCmdArgs[1:]...)

		if exitCode != 0 {
			log.Error().Msgf("Failed to schedule uninstall: %s", output)
			_, _, _ = h.Executor.RunAsUser(ctx, "root", "sh", "-c", cmd)
		}
	} else {
		// Defer the uninstall so the process can shut down cleanly first.
		// Use a subshell background pattern instead of nohup, which may not
		// be available in minimal container images.
		deferredCmd := fmt.Sprintf("(sleep 5 && %s) >>%s/alpamon.log 2>&1 &", cmd, utils.LogDir())
		log.Info().Msg("Systemd not available, scheduling deferred uninstall.")
		_, _, _ = h.Executor.RunAsUser(ctx, "root", "sh", "-c", deferredCmd)
	}

	// Shutdown the process after scheduling
	h.wsClient.ShutDown()
}

// handleReboot handles the reboot command.
// A separate context is created via ctxManager.NewContext instead of using the
// handler's ctx because the response must be sent before the reboot executes.
// The pool task runs asynchronously after the handler returns. The context is
// still derived from ContextManager.root, so shutdown propagation works correctly.
func (h *SystemHandler) handleReboot() (int, string, error) {
	log.Info().Msg("Reboot request received.")

	poolCtx, cancel := h.ctxManager.NewContext(common.SystemCmdTimeout)
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

// handleShutdown handles the shutdown command.
// See handleReboot for why a separate context is created.
func (h *SystemHandler) handleShutdown() (int, string, error) {
	log.Info().Msg("Shutdown request received.")

	poolCtx, cancel := h.ctxManager.NewContext(common.SystemCmdTimeout)
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
	switch utils.PlatformLike {
	case "debian":
		cmd = "apt-get update -o Acquire::Retries=3 && apt-get upgrade -y -o Acquire::Retries=3 && apt-get autoremove -y"
	case "rhel":
		cmd = "yum update -y"
	case "darwin":
		cmd = "brew upgrade"
	default:
		return 1, fmt.Sprintf("Platform '%s' not supported.", utils.PlatformLike), nil
	}

	exitCode, output, err := h.Executor.RunAsUser(ctx, "root", "sh", "-c", cmd)
	return exitCode, output, err
}
