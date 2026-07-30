package system

import (
	"context"
	"errors"
	"fmt"
	"net/url"
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

	// uninstallDelay defers executeUninstall so the byebye response is sent
	// before the agent starts tearing itself down. Tests shorten it and use
	// uninstallDone to drain the timer goroutine, which would otherwise
	// outlive the test and race on package-level state (utils.PlatformLike).
	uninstallDelay time.Duration
	// uninstallDone, when non-nil, is closed after executeUninstall returns.
	uninstallDone chan struct{}
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
//
// args.PackageProxy, when present, routes the GitHub version lookup and the
// package-manager shell through the given proxy so closed-network deployments
// with an outbound proxy can upgrade. A failed version lookup is not fatal on
// linux: "latest" is delegated to the package manager instead.
func (h *SystemHandler) handleUpgrade(ctx context.Context, args *common.CommandArgs) (int, string, error) {
	var packageProxy string
	if args != nil {
		packageProxy = sanitizePackageProxy(args.PackageProxy)
	}

	latestVersion := h.versionResolver.GetLatestVersion(packageProxy)
	if latestVersion == "" {
		// Closed-network deployments may not be able to reach api.github.com.
		// Delegate "latest" to the package manager instead of failing here.
		log.Warn().Msg("Failed to retrieve the latest Alpamon version from GitHub; proceeding with package manager upgrade.")
	}

	needAlpamon := latestVersion == "" || version.Version != latestVersion

	currentPamVersion := h.versionResolver.GetPamVersion()
	needPam := currentPamVersion != "" && (latestVersion == "" || currentPamVersion != latestVersion)

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
	// Set when the refresh was scoped to alpamon's own repo, which is what makes
	// a later "some repos were skipped" tolerable; see normalizeZypperExit.
	var alpamonRepoRefreshed bool
	// Populated on the zypper path only, to catch an update that exits 0 without
	// moving anything; see unmovedPackages.
	var versionsBefore map[string]string
	switch utils.PackageManager {
	case utils.PkgApt:
		cmd = fmt.Sprintf("apt-get update -y -o Acquire::Retries=3 && apt-get install --only-upgrade %s -y -o Acquire::Retries=3", pkgList)
	case utils.PkgYum:
		cmd = fmt.Sprintf("yum update -y %s", pkgList)
	case utils.PkgZypper:
		// The refresh is explicit because zypper only auto-refreshes repos added
		// with autorefresh on (`addrepo -f`), and against stale metadata `update`
		// finds no candidate and still exits 0. It runs as its own command because
		// chaining it with `&&` lets one unreachable repo anywhere on the host exit
		// 4 with update never running, and hides which half produced the code. The
		// update stays unscoped: `update -r` loads only that repo and then cannot
		// resolve dependencies from the distribution repos.
		refresh := []string{"zypper", "--non-interactive", "refresh"}
		if alias := h.resolveZypperAlpamonRepo(ctx); alias != "" {
			refresh = append(refresh, alias)
			alpamonRepoRefreshed = true
		}
		code, out, rerr := retryWhileZypperLocked(ctx, func() (int, string, error) {
			return h.Executor.Exec(ctx, refresh, "root", "root", packageProxyEnv(packageProxy), 0)
		})
		if code != 0 {
			return code, out, rerr
		}
		cmd = fmt.Sprintf("zypper --non-interactive update %s", pkgList)
		versionsBefore = h.installedRPMVersions(ctx, packages)
	case utils.PkgBrew, utils.PkgNone:
		// darwin/windows have no package channel for alpamon, so the binary
		// replaces itself. needAlpamon is always true here: needPam is always
		// false on non-linux (pam unsupported; see pkg/utils/pam.go) and the
		// switch is reached only when needAlpamon||needPam.
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
			note := fmt.Sprintf(
				"zypper exited 0 but %s did not move (still %s). The repository may not carry a newer "+
					"build yet, or its vendor changed: solver.allowVendorChange is off by default, and "+
					"zypper then declines the upgrade without failing.",
				strings.Join(stale, ", "), versionsBefore[stale[0]])
			log.Warn().Msg(note)
			output = strings.TrimRight(output, "\n") + "\n\n" + note
		}
	}
	if exitCode == 0 && needPam {
		h.versionResolver.InvalidatePamCache()
	}
	return exitCode, output, err
}

// sanitizePackageProxy validates the payload-provided proxy URL once at
// handleUpgrade entry. An invalid or unsupported value is treated as absent
// for BOTH the version lookup and the package-manager shell environment, so
// the two paths stay consistent (no half-applied proxy in the root shell).
// The raw value is never logged because proxy URLs may embed credentials
// (user:pass@); the scheme alone is safe to log.
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

// zypper behavior the other package managers do not share; per-code reasoning and the apt/yum contrast are in docs/opensuse.md.
const (
	// The PackageCloud repository carrying alpamon, whatever alias the operator gave it.
	alpamonRepoURL = "packagecloud.io/alpacax/alpamon"

	// ZYPP_LOCKED: packagekit, an operator's session, or a console update racing
	// the agent's own upgrade holds the libzypp lock. dnf waits for its lock and
	// apt can be told to retry; zypper --non-interactive gives up at once.
	zypperLockedExit   = 7
	zypperLockAttempts = 3
)

// Var so tests do not sleep. Long enough for a short transaction elsewhere to finish, short enough to stay inside a console command's patience.
var zypperLockRetryDelay = 15 * time.Second

// Test seam: the uninstall scheduling it gates is linux-only, so without it the
// path cannot be exercised from a darwin or windows test run.
var hasSystemd = utils.HasSystemd

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

// Packages an upgrade left in place after reporting success. zypper keeps
// solver.allowVendorChange off, so a vendor change in a published build makes
// `update` print "No update candidate" and exit 0 with the old version still
// installed, which is the silent no-op the explicit refresh cannot catch. apt and
// yum have no vendor gate, so versionsBefore is empty there and this is a no-op.
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

// 102/103 follow a successful install; every other code stays a failure, and the
// dropped error is the *exec.ExitError for the same code. 106 (some repos skipped)
// is success only when alpamonRepoRefreshed says the repo we depend on was
// refreshed on its own, so the skipped one cannot hide a missed update.
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

// packageProxyEnv builds the proxy environment for the package-manager shell
// in closed-network deployments. It returns nil when no proxy is configured,
// which keeps behavior identical to an env-less invocation. no_proxy excludes
// the Alpacon server host, the IMDS endpoints (AWS IPv4/IPv6, GCP), and
// localhost as a safeguard so
// nothing spawned by the upgrade can route control-plane or metadata traffic
// through the package proxy.
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

// executeUninstall performs the actual uninstall.
// Three-step sequence: (1) tell the console to drop our server record so the
// agent stops appearing in the inventory, (2) schedule the package removal so
// it survives our own shutdown, (3) shut the agent down. Step (1) is
// best-effort: any failure is logged and the rest of the sequence still runs,
// otherwise a network blip would leave the binary uninstallable.
func (h *SystemHandler) executeUninstall() {
	h.unregisterFromConsole()

	var cmd string

	switch utils.PackageManager {
	case utils.PkgApt:
		// Use purge to remove package and config files
		cmd = "apt-get purge alpamon -y && apt-get autoremove -y"
	case utils.PkgYum:
		cmd = "yum remove alpamon -y"
	case utils.PkgZypper:
		cmd = "zypper --non-interactive remove alpamon"
	case utils.PkgBrew:
		// For macOS development environment, just shutdown
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
		// Build the complete uninstall command that includes:
		// 1. Package removal
		// 2. Cleanup of transient systemd units created by this operation
		uninstallCmd := fmt.Sprintf("%s; systemctl reset-failed alpamon-uninstall.service 2>/dev/null || true; systemctl reset-failed alpamon-uninstall.timer 2>/dev/null || true", cmd)

		// This ensures the uninstall continues even after the current process terminates
		// The service will start 5 seconds after being scheduled
		scheduleCmdArgs := []string{
			"--uid=0",
			"--gid=0",
			"--unit=alpamon-uninstall",
			"--timer-property=OnActiveSec=5",
			"--timer-property=AccuracySec=1s",
			"--description=Alpamon Uninstall Service",
			"/bin/sh", "-c", uninstallCmd,
		}

		// --collect cleans the transient units up on its own, but it needs systemd
		// 236+ and SLES 12, which the SUSE prefixes accept, ships 228. Retry
		// without it before falling back: the fallback removes the package
		// synchronously, which tears the agent down mid-command. The reset-failed
		// calls above already cover what --collect would have done.
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
	switch utils.PackageManager {
	case utils.PkgApt:
		cmd = "apt-get update -o Acquire::Retries=3 && apt-get upgrade -y -o Acquire::Retries=3 && apt-get autoremove -y"
	case utils.PkgYum:
		cmd = "yum update -y"
	case utils.PkgZypper:
		// Tumbleweed is a rolling release: `zypper update` cannot perform the
		// vendor changes a distribution upgrade needs. Leap/SLES must NOT use
		// dup: it would jump to the next service pack.
		//
		// The refresh mirrors the apt branch's `apt-get update`; see handleUpgrade
		// for why zypper cannot be relied on to refresh itself.
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
	return exitCode, output, err
}
