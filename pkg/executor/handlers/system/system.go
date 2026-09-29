package system

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/alpacax/alpamon/v2/internal/pool"
	"github.com/alpacax/alpamon/v2/pkg/agent"
	"github.com/alpacax/alpamon/v2/pkg/config"
	"github.com/alpacax/alpamon/v2/pkg/executor/handlers/common"
	"github.com/alpacax/alpamon/v2/pkg/updater"
	"github.com/alpacax/alpamon/v2/pkg/utils"
	"github.com/alpacax/alpamon/v2/pkg/version"
	"github.com/rs/zerolog/log"
)

// unregisterURL is the alpacon-server endpoint that removes the server record for this agent;
// the `-` placeholder resolves server-side to the caller's own id.
const unregisterURL = "/api/servers/servers/-/unregister/"

// unregisterTimeoutSeconds bounds byebye's DELETE call so an unreachable console cannot stall removal.
// Not a Duration: Session methods multiply by time.Second, so 10*time.Second would be about 1e9 times too long.
const unregisterTimeoutSeconds = 10

// delayedActionDelay lets restart, quit, reboot and shutdown send their response before acting.
// Pool.Shutdown cannot interrupt a sleeping job, so any drain budget must outlast this delay.
const delayedActionDelay = 1 * time.Second

// Fails the build if delayedActionDelay stops matching the "1 second" spelled out below.
// Blank so the unused linter reads it as the compile-time assertion it is.
const _ = uint(delayedActionDelay-time.Second) + uint(time.Second-delayedActionDelay)

// zypper behavior the other package managers do not share; per-code reasoning and the apt/yum contrast are in docs/opensuse.md.
const (
	// The PackageCloud repository carrying alpamon, whatever alias the operator gave it.
	// The trailing slash keeps alpamon-dev and alpamon-latest from matching;
	// packagecloud always puts a path segment after the repo name.
	alpamonRepoURL = "packagecloud.io/alpacax/alpamon/"

	// ZYPP_LOCKED: packagekit, an operator session, or a racing console update holds the libzypp lock.
	// dnf waits for its lock and apt can be told to retry; zypper --non-interactive gives up at once.
	zypperLockedExit   = 7
	zypperLockAttempts = 3
)

// Var so tests do not sleep. Long enough for a short transaction elsewhere to finish, short enough to stay inside a console command's patience.
var zypperLockRetryDelay = 15 * time.Second

// aptSourcesDir is where apt reads source files from. Var so tests point it at a temp dir.
var aptSourcesDir = "/etc/apt/sources.list.d"

// Test seam: the uninstall scheduling it gates is linux-only, so without it the
// path cannot be exercised from a darwin or windows test run.
var hasSystemd = utils.HasSystemd

// apt's false spellings for a deb822 "Enabled:" field; anything else, including
// a missing field, counts as enabled.
var deb822FalseValues = map[string]bool{
	"no": true, "false": true, "without": true, "off": true, "disable": true, "0": true,
}

// SystemHandler handles system-level commands like restart, reboot, shutdown, upgrade
type SystemHandler struct {
	*common.BaseHandler
	wsClient        common.WSClient
	ctxManager      *agent.ContextManager
	pool            *pool.Pool
	versionResolver common.VersionResolver
	apiSession      common.APISession
	selfUpdateFn    updater.SelfUpdateFunc // defaults to updater.SelfUpdate; tests inject a fake
	// defaults to updater.PinnedSelfUpdate; tests inject a fake.
	pinnedUpdateFn func(ctx context.Context, req updater.PinnedRequest, opts updater.Options) error
	// serviceManager restarts the agent from outside after a pinned upgrade
	// and arms its guard; tests inject a fake.
	serviceManager updater.ServiceManager
	now            func() time.Time

	// uninstallDelay defers executeUninstall until after the byebye response is sent.
	// Tests shorten it and drain via uninstallDone to avoid outliving the test and racing utils.PlatformLike.
	uninstallDelay time.Duration
	// uninstallDone, when non-nil, is closed after executeUninstall returns.
	uninstallDone chan struct{}
}

// NewSystemHandler creates a new system handler; versionResolver must not be nil (use
// utils.NewDefaultVersionResolver() in production). apiSession may be nil in tests.
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
		pinnedUpdateFn:  updater.PinnedSelfUpdate,
		serviceManager:  updater.DefaultServiceManager(),
		now:             time.Now,
		uninstallDelay:  1 * time.Second,
	}
	return h
}

// Execute runs the system command
func (h *SystemHandler) Execute(ctx context.Context, cmd string, args *common.CommandArgs) (int, string, error) {
	switch cmd {
	case common.Upgrade.String():
		return h.withTimeout(ctx, common.UpgradeTimeout, func(ctx context.Context) (int, string, error) {
			return h.handleUpgrade(ctx, args)
		})
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
	return nil // most system commands do not require arguments
}

// handleUpgrade checks alpamon and alpamon-pam versions independently and upgrades only what
// needs it, so a pam-only update is not skipped when alpamon is already current.
func (h *SystemHandler) handleUpgrade(ctx context.Context, args *common.CommandArgs) (int, string, error) {
	var packageProxy string
	if args != nil {
		packageProxy = sanitizePackageProxy(args.PackageProxy)
		// A target version switches to the pinned path; without one the
		// legacy path below runs exactly as it did before pinning existed.
		if args.Upgrade != nil {
			return h.handlePinnedUpgrade(ctx, args.Upgrade, packageProxy)
		}
	}

	latestVersion := h.versionResolver.GetLatestVersion(packageProxy)
	if latestVersion == "" {
		// Closed-network deployments may not be able to reach api.github.com.
		// Delegate "latest" to the package manager instead of failing here.
		log.Warn().Msg("Failed to retrieve the latest Alpamon version from GitHub; proceeding with package manager upgrade.")
	}

	// goreleaser strips the tag's leading "v" into version.Version, but GetLatestVersion keeps it;
	// comparing as-is always looked outdated and drove a needless self-update and restart every time.
	needAlpamon := latestVersion == "" || !sameVersion(version.Version, latestVersion)

	// alpamon-pam versions independently of alpamon, so alpamon's tag says nothing about whether pam
	// is current. The package manager alone decides: pam joins the transaction whenever installed.
	currentPamVersion := h.versionResolver.GetPamVersion()
	needPam := currentPamVersion != ""

	// Reached only when alpamon-pam is absent, since an installed one always
	// goes to the package manager.
	if !needAlpamon && !needPam {
		return 0, fmt.Sprintf("Already up-to-date (alpamon: %s, pam: not installed)", version.Version), nil
	}

	var packages []string
	if needAlpamon {
		packages = append(packages, "alpamon")
	}
	if needPam {
		packages = append(packages, "alpamon-pam")
	}
	pkgList := strings.Join(packages, " ")

	// A package upgrade must not run in the middle of a pinned upgrade: take the upgrade latch and
	// refuse while a pinned attempt is still pending. Self updates take the latch themselves.
	switch utils.PackageManager {
	case utils.PkgApt, utils.PkgYum, utils.PkgZypper:
		if !updater.AcquireUpgradeLatch() {
			return 0, "Upgrade already in progress.", nil
		}
		defer updater.ReleaseSelfUpdateLatch()
		if err := updater.CheckNoPending(h.serviceManager, h.now()); err != nil {
			if errors.Is(err, updater.ErrUpgradePending) {
				log.Warn().Err(err).Msg("Refusing a package upgrade while a pinned upgrade is pending.")
				return 1, fmt.Sprintf("Upgrade refused: %v. Retry once it completes.", err), err
			}
			log.Warn().Err(err).Msg("Could not check for a pending pinned upgrade; continuing.")
		}
	}

	var cmd string
	// Set when the refresh was scoped to alpamon's own repo, which is what makes
	// a later "some repos were skipped" tolerable; see normalizeZypperExit.
	var alpamonRepoRefreshed bool
	// Populated on the zypper path only, to catch an update that exits 0 without
	// moving anything; see unmovedPackages.
	var versionsBefore map[string]string
	switch utils.PackageManager {
	case utils.PkgApt:
		// Scoped to alpamon's source and run apart from install: one broken repo
		// elsewhere on the host must not block the upgrade, and a failure must name its step.
		argv := aptUpdateArgv(resolveAptAlpamonSource())
		code, out, rerr := h.Executor.Exec(ctx, argv, "root", "root", packageProxyEnv(packageProxy), 0)
		if code != 0 {
			return code, appendStepFailure(out, "apt-get update", code, rerr), rerr
		}
		cmd = fmt.Sprintf("apt-get install --only-upgrade %s -y -o Acquire::Retries=3", pkgList)
	case utils.PkgYum:
		cmd = fmt.Sprintf("yum update -y %s", pkgList)
	case utils.PkgZypper:
		// Refresh runs as its own command: chaining it with `&&` lets one unreachable repo exit 4 so update
		// never runs, hiding the failing step. `update -r` loads only that repo, so it cannot resolve distro deps.
		refresh := []string{"zypper", "--non-interactive", "refresh"}
		if alias := h.resolveZypperAlpamonRepo(ctx); alias != "" {
			refresh = append(refresh, alias)
			alpamonRepoRefreshed = true
		}
		code, out, rerr := retryWhileZypperLocked(ctx, func() (int, string, error) {
			return h.Executor.Exec(ctx, refresh, "root", "root", packageProxyEnv(packageProxy), 0)
		})
		if code != 0 {
			return code, withZypperHint(code, out), rerr
		}
		cmd = fmt.Sprintf("zypper --non-interactive update %s", pkgList)
		versionsBefore = h.installedRPMVersions(ctx, packages)
	case utils.PkgBrew, utils.PkgNone:
		// darwin and windows have no package channel for alpamon, so the binary replaces itself. needAlpamon is
		// always true here: needPam is false off linux (see pkg/utils/pam.go) and one of the two must be set.
		if latestVersion == "" {
			// Self-update needs a concrete target version; there is no
			// package manager to delegate "latest" to on these platforms.
			return 1, "Failed to retrieve the latest Alpamon version from GitHub.",
				errors.New("failed to retrieve the latest Alpamon version from GitHub")
		}
		return h.selfUpdate(ctx, latestVersion)
	default:
		return 1, fmt.Sprintf("Platform '%s' (package manager %q) not supported.", utils.PlatformLike, utils.PackageManager), nil
	}

	log.Debug().Msgf("Upgrading %s...", pkgList)
	// The proxy environment (nil without a package proxy) applies to the
	// spawned package-manager shell only, never to the agent process.
	exitCode, output, err := retryWhileZypperLocked(ctx, func() (int, string, error) {
		return h.Executor.Exec(ctx, []string{"sh", "-c", cmd}, "root", "root", packageProxyEnv(packageProxy), 0)
	})
	exitCode, err = normalizeZypperExit(exitCode, err, alpamonRepoRefreshed)
	// Reported, not failed: a repository that has not published the new build yet
	// is routine, and the console already shows the version the agent reports.
	if exitCode == 0 {
		if stale := h.unmovedPackages(ctx, versionsBefore); len(stale) > 0 {
			// Per package: alpamon and alpamon-pam carry their own version-release,
			// so one shared number would misname the other one's.
			held := make([]string, 0, len(stale))
			for _, pkg := range stale {
				held = append(held, fmt.Sprintf("%s (still %s)", pkg, versionsBefore[pkg]))
			}
			note := fmt.Sprintf(
				"zypper exited 0 but %s did not move. The repository may not carry a newer "+
					"build yet, or its vendor changed: solver.allowVendorChange is off by default, and "+
					"zypper then declines the upgrade without failing.",
				strings.Join(held, ", "))
			log.Warn().Msg(note)
			output = strings.TrimRight(output, "\n") + "\n\n" + note
		}
	}
	output = withZypperHint(exitCode, output)
	if utils.PackageManager == utils.PkgApt && exitCode != 0 {
		output = appendStepFailure(output, "apt-get install", exitCode, err)
	}
	if exitCode == 0 && needPam {
		h.versionResolver.InvalidatePamCache()
	}
	return exitCode, output, err
}

// The alias to scope the refresh to, or "" when none resolves. `lr --export -` is
// parsed rather than the table form: it emits ini and needs no column splitting.
func (h *SystemHandler) resolveZypperAlpamonRepo(ctx context.Context) string {
	exitCode, output, err := h.Executor.RunAsUser(ctx, "root", "zypper", "--non-interactive", "lr", "--export", "-")
	if err != nil || exitCode != 0 {
		log.Debug().Int("exitCode", exitCode).Msg("Could not list zypper repositories; upgrading without a repo scope.")
		return ""
	}

	var alias string
	enabled, matched := true, false
	resolved := func() string {
		if matched && enabled {
			return alias
		}
		return ""
	}

	for line := range strings.SplitSeq(output, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]"):
			if got := resolved(); got != "" {
				return got
			}
			alias = strings.TrimSuffix(strings.TrimPrefix(line, "["), "]")
			enabled, matched = true, false
		case strings.HasPrefix(line, "enabled="):
			enabled = strings.TrimPrefix(line, "enabled=") == "1"
		case strings.Contains(line, alpamonRepoURL):
			matched = true
		}
	}
	return resolved()
}

// version-release of each package rpm can report, skipping the rest.
func (h *SystemHandler) installedRPMVersions(ctx context.Context, packages []string) map[string]string {
	versions := make(map[string]string, len(packages))
	for _, pkg := range packages {
		exitCode, output, err := h.Executor.RunAsUser(ctx, "root", "rpm", "-q", "--qf", "%{VERSION}-%{RELEASE}", pkg)
		if err != nil || exitCode != 0 {
			continue
		}
		versions[pkg] = strings.TrimSpace(output)
	}
	return versions
}

// Packages an upgrade left in place after reporting success: zypper keeps solver.allowVendorChange off, so a
// vendor change prints "No update candidate" and exits 0 with the old version. Empty on apt and yum.
func (h *SystemHandler) unmovedPackages(ctx context.Context, versionsBefore map[string]string) []string {
	var stale []string
	for pkg, before := range versionsBefore {
		if after, ok := h.installedRPMVersions(ctx, []string{pkg})[pkg]; ok && after == before {
			stale = append(stale, pkg)
		}
	}
	slices.Sort(stale)
	return stale
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

	if err := h.scheduleDelayedAction(delayedActionDelay, func(_ context.Context) {
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

// scheduleDelayedAction runs a function on the worker pool after a delay, for fire-and-forget
// operations like restart and shutdown whose response must be sent before the action runs.
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

// handleRestart is fire-and-forget: it returns immediately while the restart runs asynchronously
// on the pool with its own context from ctxManager. Execute's timeout covers only the dispatch.
func (h *SystemHandler) handleRestart(args *common.CommandArgs) (int, string, error) {
	if args.Target == "collector" {
		log.Info().Msg("Restart collector.")
		h.wsClient.RestartCollector()
		return 0, "Collector will be restarted.", nil
	}

	if err := h.scheduleDelayedAction(delayedActionDelay, func(_ context.Context) {
		h.wsClient.Restart()
	}); err != nil {
		log.Error().Err(err).Msg("Failed to submit restart task to pool")
	}
	return 0, "Alpamon will restart in 1 second.", nil
}

// handleQuit handles the quit command.
// See scheduleDelayedAction for the fire-and-forget pattern.
func (h *SystemHandler) handleQuit() (int, string, error) {
	if err := h.scheduleDelayedAction(delayedActionDelay, func(_ context.Context) {
		h.wsClient.ShutDown()
	}); err != nil {
		log.Error().Err(err).Msg("Failed to submit quit task to pool")
	}
	return 0, "Alpamon will shutdown in 1 second.", nil
}

// unregisterFromConsole issues DELETE /api/servers/servers/-/unregister/ so alpacon-server drops
// this server's record. Best effort: a failure is logged and ignored so the agent still purges itself.
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

// handleUninstall handles the byebye command; see handleRestart for the fire-and-forget pattern.
// executeUninstall uses context.Background() since uninstall must finish after shutdown begins.
func (h *SystemHandler) handleUninstall() (int, string, error) {
	log.Info().Msg("Uninstall request received.")

	// Execute uninstall after a delay (1 second in production) to ensure the
	// response is sent first.
	time.AfterFunc(h.uninstallDelay, func() {
		h.executeUninstall()
		if h.uninstallDone != nil {
			close(h.uninstallDone)
		}
	})

	return 0, "Starting uninstall process...", nil
}

// executeUninstall: (1) best effort console unregister so a network blip cannot block the rest,
// (2) schedules package removal so it survives our shutdown, (3) shuts the agent down.
func (h *SystemHandler) executeUninstall() {
	h.unregisterFromConsole()

	var cmd string

	switch utils.PackageManager {
	case utils.PkgApt:
		// purge removes package and config files
		cmd = "apt-get purge alpamon -y && apt-get autoremove -y"
	case utils.PkgYum:
		cmd = "yum remove alpamon -y"
	case utils.PkgZypper:
		cmd = "zypper --non-interactive remove alpamon"
	case utils.PkgBrew:
		log.Warn().Msgf("Platform '%s' does not support full uninstall. Shutting down instead.", utils.PlatformLike)
		h.wsClient.ShutDown()
		return
	default:
		log.Error().Msgf("Platform '%s' (package manager %q) not supported for uninstall.", utils.PlatformLike, utils.PackageManager)
		h.wsClient.ShutDown()
		return
	}

	ctx := context.Background()

	if hasSystemd() {
		uninstallCmd := fmt.Sprintf("%s; systemctl reset-failed alpamon-uninstall.service 2>/dev/null || true; systemctl reset-failed alpamon-uninstall.timer 2>/dev/null || true", cmd)

		// --on-active, not --timer-property=OnActiveSec, because systemd before 236 rejects a
		// --timer-property with no other timer option set (measured on systemd 229 and 228).
		scheduleCmdArgs := []string{
			"--uid=0",
			"--gid=0",
			"--unit=alpamon-uninstall",
			"--on-active=5",
			"--timer-property=AccuracySec=1s",
			"--description=Alpamon Uninstall Service",
			"/bin/sh", "-c", uninstallCmd,
		}

		// --collect needs systemd 236 or later; SUSE's own prefixes ship 228, so retry without it first.
		// The fallback removes the package synchronously, which tears the agent down mid command.
		withCollect := append([]string{"--collect"}, scheduleCmdArgs...)
		exitCode, output, _ := h.Executor.RunWithTimeout(ctx, 30*time.Second, "systemd-run", withCollect...)
		if exitCode != 0 {
			log.Warn().Msgf("Could not schedule uninstall with --collect, retrying without it: %s", output)
			exitCode, output, _ = h.Executor.RunWithTimeout(ctx, 30*time.Second, "systemd-run", scheduleCmdArgs...)
		}

		if exitCode != 0 {
			log.Error().Msgf("Failed to schedule uninstall: %s", output)
			_, _, _ = h.Executor.RunAsUser(ctx, "root", "sh", "-c", cmd)
		}
	} else {
		// Defer the uninstall so the process can shut down cleanly first.
		// Uses a subshell background pattern instead of nohup, which may be missing in minimal images.
		deferredCmd := fmt.Sprintf("(sleep 5 && %s) >>%s/alpamon.log 2>&1 &", cmd, utils.LogDir())
		log.Info().Msg("Systemd not available, scheduling deferred uninstall.")
		_, _, _ = h.Executor.RunAsUser(ctx, "root", "sh", "-c", deferredCmd)
	}

	h.wsClient.ShutDown()
}

// handleReboot handles the reboot command; the pool task runs after the handler returns so the
// response is sent before the reboot fires. See scheduleDelayedAction.
func (h *SystemHandler) handleReboot() (int, string, error) {
	log.Info().Msg("Reboot request received.")

	if err := h.scheduleDelayedAction(delayedActionDelay, func(ctx context.Context) {
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

	if err := h.scheduleDelayedAction(delayedActionDelay, func(ctx context.Context) {
		_, _, _ = h.Executor.RunAsUser(ctx, "root", "shutdown", "now")
	}); err != nil {
		log.Error().Err(err).Msg("Failed to submit shutdown task to pool")
	}
	return 0, "Server will shutdown in 1 second", nil
}

func (h *SystemHandler) handleSystemUpdate(ctx context.Context) (int, string, error) {
	log.Info().Msg("Upgrade system requested.")

	var cmd string
	switch utils.PackageManager {
	case utils.PkgApt:
		cmd = "apt-get update -o Acquire::Retries=3 && apt-get upgrade -y -o Acquire::Retries=3 && apt-get autoremove -y"
	case utils.PkgYum:
		cmd = "yum update -y"
	case utils.PkgZypper:
		// Tumbleweed is a rolling release and needs `zypper dup`, not `update`, for vendor changes;
		// Leap and SLES must not dup, which would jump to the next service pack.
		if utils.IsTumbleweed(utils.PlatformID) {
			cmd = "zypper --non-interactive refresh && zypper --non-interactive dup"
		} else {
			cmd = "zypper --non-interactive refresh && zypper --non-interactive update"
		}
	case utils.PkgBrew:
		cmd = "brew upgrade"
	default:
		return 1, fmt.Sprintf("Platform '%s' (package manager %q) not supported.", utils.PlatformLike, utils.PackageManager), nil
	}

	// A system-wide update covers every repo by definition, so a skipped repo
	// means part of the update did not happen: 106 stays a failure here.
	exitCode, output, err := retryWhileZypperLocked(ctx, func() (int, string, error) {
		return h.Executor.RunAsUser(ctx, "root", "sh", "-c", cmd)
	})
	exitCode, err = normalizeZypperExit(exitCode, err, false)
	return exitCode, withZypperHint(exitCode, output), err
}

// sameVersion reports whether two version strings name the same release, ignoring a leading
// "v" on either side. The build injected version has it stripped; a release tag keeps it.
func sameVersion(a, b string) bool {
	return strings.TrimPrefix(a, "v") == strings.TrimPrefix(b, "v")
}

// sanitizePackageProxy validates the payload proxy URL once; an invalid value counts as absent for both the
// version lookup and the package manager environment. Never log the raw value: it may embed credentials.
func sanitizePackageProxy(raw string) string {
	if raw == "" {
		return ""
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Hostname() == "" {
		log.Warn().Msg("Invalid package proxy URL in upgrade payload; ignoring it.")
		return ""
	}
	switch parsed.Scheme {
	case "http", "https", "socks5", "socks5h":
		return raw
	default:
		log.Warn().Str("scheme", parsed.Scheme).Msg("Unsupported package proxy scheme in upgrade payload; ignoring it.")
		return ""
	}
}

// aptUpdateArgv builds the "apt-get update" argv, scoped to alpamonSource when
// non-empty. The arg order is fixed: callers and tests key on it.
func aptUpdateArgv(alpamonSource string) []string {
	argv := []string{"apt-get", "update", "-y", "-o", "Acquire::Retries=3"}
	if alpamonSource != "" {
		argv = append(argv,
			"-o", "Dir::Etc::sourcelist="+alpamonSource,
			"-o", "Dir::Etc::sourceparts=-",
			"-o", "APT::Get::List-Cleanup=0",
		)
	}
	return argv
}

// resolveAptAlpamonSource returns the full path of the apt source file that
// carries alpamon's enabled packagecloud repository, or "" when none resolves.
func resolveAptAlpamonSource() string {
	entries, err := os.ReadDir(aptSourcesDir)
	if err != nil {
		log.Debug().Err(err).Msg("Could not list apt source files; refreshing without a scope.")
		return ""
	}

	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !(strings.HasSuffix(name, ".list") || strings.HasSuffix(name, ".sources")) {
			continue
		}
		path := filepath.Join(aptSourcesDir, name)
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		var matched bool
		if strings.HasSuffix(name, ".sources") {
			matched = hasEnabledAlpamonStanza(string(data))
		} else {
			matched = hasActiveAlpamonLine(string(data))
		}
		if matched {
			log.Debug().Str("path", path).Msg("Scoping the apt refresh to the alpamon source.")
			return path
		}
	}
	log.Debug().Msg("Could not resolve the alpamon apt source; refreshing without a scope.")
	return ""
}

func hasActiveAlpamonLine(data string) bool {
	for line := range strings.SplitSeq(data, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.Contains(line, alpamonRepoURL) {
			return true
		}
	}
	return false
}

func hasEnabledAlpamonStanza(data string) bool {
	enabled, matched := true, false
	resolved := func() bool { return matched && enabled }

	for line := range strings.SplitSeq(data, "\n") {
		trimmed := strings.TrimSpace(line)
		switch {
		case trimmed == "":
			if resolved() {
				return true
			}
			enabled, matched = true, false
		case strings.HasPrefix(trimmed, "#"):
			continue
		default:
			if key, value, ok := strings.Cut(trimmed, ":"); ok && strings.EqualFold(strings.TrimSpace(key), "enabled") {
				enabled = !deb822FalseValues[strings.ToLower(strings.TrimSpace(value))]
			}
			if strings.Contains(trimmed, alpamonRepoURL) {
				matched = true
			}
		}
	}
	return resolved()
}

// appendStepFailure returns output with the failed step and its exit code appended,
// since the package manager's own error text does not say which step produced it.
func appendStepFailure(output, step string, code int, err error) string {
	return strings.TrimRight(output, "\n") + "\n\n" + commandFailed(step, code, err).Error()
}

func retryWhileZypperLocked(ctx context.Context, run func() (int, string, error)) (int, string, error) {
	for attempt := 1; ; attempt++ {
		exitCode, output, err := run()
		if exitCode != zypperLockedExit || utils.PackageManager != utils.PkgZypper || attempt >= zypperLockAttempts {
			return exitCode, output, err
		}
		log.Info().Int("attempt", attempt).Msg("zypper is locked by another process; retrying.")
		select {
		case <-ctx.Done():
			return exitCode, output, err
		case <-time.After(zypperLockRetryDelay):
		}
	}
}

// The console only shows the exit code and output, and zypper's own text does not say what to fix.
// Measured on an unregistered sles12sp5: `lr` exits 6 and `update alpamon` exits 104, neither naming why.
func withZypperHint(exitCode int, output string) string {
	if utils.PackageManager != utils.PkgZypper {
		return output
	}

	var hint string
	switch exitCode {
	case 4:
		hint = "A repository could not be refreshed. One unreachable repository fails the whole " +
			"command, even when alpamon's own repository is fine: check `zypper lr --uri`."
	case 6:
		hint = "No repositories are defined. On SLES this usually means the host has no active " +
			"subscription (`SUSEConnect --status`); alpamon's repository also has to be added with " +
			"`zypper addrepo`, because the PackageCloud one-liner writes a yum repo file zypper never reads."
	case zypperLockedExit:
		hint = "Another process still holds the libzypp lock after several retries. Find it with " +
			"`zypper ps`, and expect packagekit or an operator's own zypper session."
	case 104:
		hint = "No configured repository carries the package. Add alpamon's repository with " +
			"`zypper addrepo`, and on SLES check that the subscription is active (`SUSEConnect --status`)."
	case 106:
		hint = "A repository was skipped because it failed to refresh, so the update may have missed " +
			"packages: `zypper refresh` names the one that failed."
	default:
		return output
	}
	return strings.TrimRight(output, "\n") + "\n\n" + hint
}

// 102 and 103 follow a successful install; every other code stays a failure.
// 106 (some repos skipped) is success only when alpamonRepoRefreshed confirms our own repo refreshed.
func normalizeZypperExit(exitCode int, err error, alpamonRepoRefreshed bool) (int, error) {
	if utils.PackageManager != utils.PkgZypper {
		return exitCode, err
	}
	switch {
	case exitCode == 102, exitCode == 103, exitCode == 106 && alpamonRepoRefreshed:
		log.Info().Int("zypperExitCode", exitCode).Msg("zypper reported an informational exit code; treating the command as successful.")
		return 0, nil
	}
	return exitCode, err
}

// packageProxyEnv builds the proxy environment for the package manager process in closed network
// setups; nil means no proxy. no_proxy excludes the Alpacon host, the IMDS endpoints, and localhost.
func packageProxyEnv(proxyURL string) map[string]string {
	if proxyURL == "" {
		return nil
	}

	noProxy := "localhost,127.0.0.1,::1,169.254.169.254,fd00:ec2::254,metadata.google.internal"
	if serverURL, err := url.Parse(config.GlobalSettings.ServerURL); err == nil && serverURL.Hostname() != "" {
		noProxy += "," + serverURL.Hostname()
	}

	return map[string]string{
		"http_proxy":  proxyURL,
		"https_proxy": proxyURL,
		"HTTP_PROXY":  proxyURL,
		"HTTPS_PROXY": proxyURL,
		"no_proxy":    noProxy,
		"NO_PROXY":    noProxy,
	}
}
