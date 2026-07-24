package system

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/alpacax/alpamon/v2/internal/pool"
	"github.com/alpacax/alpamon/v2/pkg/agent"
	"github.com/alpacax/alpamon/v2/pkg/executor/handlers/common"
	"github.com/alpacax/alpamon/v2/pkg/updater"
	"github.com/alpacax/alpamon/v2/pkg/utils"
	"github.com/alpacax/alpamon/v2/pkg/version"
	"github.com/rs/zerolog/log"
)

// unregisterURL is the alpacon-server endpoint that removes the server record
// corresponding to this agent. The `-` placeholder is resolved server-side to
// the authenticated agent's own server id.
const unregisterURL = "/api/servers/servers/-/unregister/"

// unregisterTimeoutSeconds bounds the DELETE call issued during byebye. Kept
// short so a network problem cannot stall the rest of the uninstall sequence;
// the package removal must still run even when the console is unreachable.
// The unit is seconds because Session.Delete (and every other Session method)
// applies *time.Second internally — naming it explicitly avoids the foot-gun
// of "fixing" this to 10*time.Second, which would balloon the deadline by ~1e9.
const unregisterTimeoutSeconds = 10

// SystemHandler handles system-level commands like restart, reboot, shutdown, upgrade
type SystemHandler struct {
	*common.BaseHandler
	wsClient        common.WSClient
	ctxManager      *agent.ContextManager
	pool            *pool.Pool
	versionResolver common.VersionResolver
	apiSession      common.APISession
	selfUpdateFn    updater.SelfUpdateFunc // defaults to updater.SelfUpdate; tests inject a fake
}

// NewSystemHandler creates a new system handler.
// versionResolver must not be nil; pass utils.NewDefaultVersionResolver() for production.
// apiSession may be nil in tests; byebye will skip the server-side unregister call when absent.
func NewSystemHandler(cmdExecutor common.CommandExecutor, wsClient common.WSClient, ctxManager *agent.ContextManager, pool *pool.Pool, versionResolver common.VersionResolver, apiSession common.APISession) *SystemHandler {
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
		apiSession:      apiSession,
		selfUpdateFn:    updater.SelfUpdate,
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
	case "darwin", "windows":
		// needAlpamon is always true here: needPam is always false on non-linux
		// (pam unsupported; see pkg/utils/pam.go) and the switch is reached only when needAlpamon||needPam.
		return h.selfUpdate(ctx, latestVersion)
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

// selfUpdate downloads and replaces the binary from GitHub Releases, then triggers restart.
func (h *SystemHandler) selfUpdate(ctx context.Context, latestVersion string) (int, string, error) {
	if err := h.selfUpdateFn(ctx, latestVersion, updater.Options{}); err != nil {
		if errors.Is(err, updater.ErrSelfUpdateInProgress) {
			// Rejecting a duplicate is correct, not a failure; the run that owns
			// the update handles its own restart, so don't schedule another.
			return 0, "Self-update already in progress.", nil
		}
		return 1, fmt.Sprintf("Self-update failed: %v", err), err
	}

	if err := h.scheduleDelayedAction(1*time.Second, func(_ context.Context) {
		h.wsClient.Restart()
	}); err != nil {
		// The update landed but no restart will fire, so drop the latch SelfUpdate
		// holds on success—otherwise a manual retry would be rejected as a duplicate.
		updater.ReleaseSelfUpdateLatch()
		log.Error().Err(err).Msg("Failed to submit restart task after self-update. Manual restart required.")
		return 1, fmt.Sprintf("Updated to %s, but automatic restart failed: %v. Please restart alpamon manually.", latestVersion, err), err
	}
	return 0, fmt.Sprintf("Updated to %s. Restarting...", latestVersion), nil
}

// scheduleDelayedAction submits a function to the worker pool that executes
// after the given delay. Used for fire-and-forget operations like restart and
// shutdown where the response must be sent before the action runs.
// The action receives the pool context for operations that need it (e.g. RunAsUser).
func (h *SystemHandler) scheduleDelayedAction(delay time.Duration, action func(ctx context.Context)) error {
	poolCtx, cancel := h.ctxManager.NewContext(delay + 1*time.Second)
	submitted := false
	defer func() {
		if !submitted {
			cancel()
		}
	}()

	err := h.pool.Submit(poolCtx, func() error {
		defer cancel()
		time.Sleep(delay)
		action(poolCtx)
		return nil
	})
	if err != nil {
		return err
	}
	submitted = true
	return nil
}

// handleRestart handles the restart command.
// This is a fire-and-forget command: the response is returned immediately and
// the actual restart runs asynchronously via the pool with its own context
// from ctxManager. The handler-level timeout in Execute() covers the synchronous
// dispatch; the pool task manages its own lifecycle via ctxManager.NewContext().
func (h *SystemHandler) handleRestart(args *common.CommandArgs) (int, string, error) {
	if args.Target == "collector" {
		log.Info().Msg("Restart collector.")
		h.wsClient.RestartCollector()
		return 0, "Collector will be restarted.", nil
	}

	if err := h.scheduleDelayedAction(1*time.Second, func(_ context.Context) {
		h.wsClient.Restart()
	}); err != nil {
		log.Error().Err(err).Msg("Failed to submit restart task to pool")
	}
	return 0, "Alpamon will restart in 1 second.", nil
}

// handleQuit handles the quit command.
// See scheduleDelayedAction for the fire-and-forget pattern.
func (h *SystemHandler) handleQuit() (int, string, error) {
	if err := h.scheduleDelayedAction(1*time.Second, func(_ context.Context) {
		h.wsClient.ShutDown()
	}); err != nil {
		log.Error().Err(err).Msg("Failed to submit quit task to pool")
	}
	return 0, "Alpamon will shutdown in 1 second.", nil
}

// unregisterFromConsole issues DELETE /api/servers/servers/-/unregister/ so
// alpacon-server removes the corresponding server record. Best-effort: a
// network failure or non-2xx response is logged and ignored so the agent can
// still purge itself locally.
func (h *SystemHandler) unregisterFromConsole() {
	if h.apiSession == nil {
		log.Debug().Msg("Skipping server unregister: no API session configured.")
		return
	}

	_, statusCode, err := h.apiSession.Delete(unregisterURL, nil, unregisterTimeoutSeconds)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to unregister server from console; continuing with local uninstall.")
		return
	}
	if statusCode < 200 || statusCode >= 300 {
		log.Warn().Int("status_code", statusCode).Msg("Server unregister returned non-2xx status; continuing with local uninstall.")
		return
	}
	log.Info().Msg("Server record removed from console.")
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

// executeUninstall performs the actual uninstall.
// Three-step sequence: (1) tell the console to drop our server record so the
// agent stops appearing in the inventory, (2) schedule the package removal so
// it survives our own shutdown, (3) shut the agent down. Step (1) is
// best-effort: any failure is logged and the rest of the sequence still runs,
// otherwise a network blip would leave the binary uninstallable.
func (h *SystemHandler) executeUninstall() {
	h.unregisterFromConsole()

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
// The pool task runs asynchronously after the handler returns so that the
// response is sent before the reboot executes. See scheduleDelayedAction.
func (h *SystemHandler) handleReboot() (int, string, error) {
	log.Info().Msg("Reboot request received.")

	if err := h.scheduleDelayedAction(1*time.Second, func(ctx context.Context) {
		_, _, _ = h.Executor.RunAsUser(ctx, "root", "reboot")
	}); err != nil {
		log.Error().Err(err).Msg("Failed to submit reboot task to pool")
	}
	return 0, "Server will reboot in 1 second", nil
}

// handleShutdown handles the shutdown command.
// See handleReboot for the fire-and-forget pattern.
func (h *SystemHandler) handleShutdown() (int, string, error) {
	log.Info().Msg("Shutdown request received.")

	if err := h.scheduleDelayedAction(1*time.Second, func(ctx context.Context) {
		_, _, _ = h.Executor.RunAsUser(ctx, "root", "shutdown", "now")
	}); err != nil {
		log.Error().Err(err).Msg("Failed to submit shutdown task to pool")
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
