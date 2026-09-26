package system

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/alpacax/alpamon/v2/pkg/executor/handlers/common"
	"github.com/alpacax/alpamon/v2/pkg/updater"
	"github.com/alpacax/alpamon/v2/pkg/utils"
	"github.com/alpacax/alpamon/v2/pkg/version"
	"github.com/rs/zerolog/log"
)

// handlePinnedUpgrade installs exactly the release the server pinned. On a
// package-managed host that is a version-pinned install through the package
// manager, whose repository signature is the trust chain; elsewhere it is the
// signature-verified self-update. There is no fallback between the two: a
// repository without the target version fails rather than dropping to a
// tarball.
func (h *SystemHandler) handlePinnedUpgrade(ctx context.Context, target *common.UpgradeTarget, packageProxy string) (int, string, error) {
	report := updater.Report{
		AttemptID:   target.AttemptID,
		FromVersion: strings.TrimPrefix(version.Version, "v"),
		ToVersion:   strings.TrimPrefix(target.TargetVersion, "v"),
	}

	tag, err := updater.NormalizeTag(target.TargetVersion)
	if err != nil {
		return h.failPinned(report, updater.Classify(updater.ClassUnknown, err), "")
	}
	report.ToVersion = strings.TrimPrefix(tag, "v")

	// Before the already-at-target shortcut: a request for the version just
	// installed must not claim success while that attempt is still pending.
	if err := updater.CheckNoPending(h.serviceManager, h.now()); err != nil {
		return h.failPinned(report, updater.Classify(updater.ClassUnknown, err), "")
	}

	if sameVersion(version.Version, tag) {
		report.Outcome = updater.OutcomeSucceeded
		report.Detail = "already running the target version"
		updater.SendReport(h.apiSession, report)
		return 0, fmt.Sprintf("Already running %s.", tag), nil
	}

	log.Info().Str("target", tag).Str("attempt_id", target.AttemptID).Msg("Pinned upgrade requested.")

	switch utils.PackageManager {
	case utils.PkgApt, utils.PkgYum, utils.PkgZypper:
		// One upgrade at a time: the latch the self-update also holds
		// serializes the pending check, the marker and the install.
		if !updater.AcquireUpgradeLatch() {
			return 0, "Upgrade already in progress.", nil
		}
		defer updater.ReleaseSelfUpdateLatch()
		// The package manager fetches from its own repositories, so the
		// artifact pins do not apply; say so rather than imply they held.
		if target.ArtifactURL != "" || target.ArtifactDigest != "" || target.ChecksumsURL != "" || target.SignatureURL != "" {
			log.Info().Msg("Artifact URL and digest are ignored on a package-managed host; the repository signature is the trust chain.")
			report.Detail = packageHostNote
		}
		return h.pinnedPackageUpgrade(ctx, report, packageProxy, target.HealthGracePeriod)
	case utils.PkgBrew, utils.PkgNone:
		return h.pinnedSelfUpdate(ctx, target, tag, report)
	default:
		err := fmt.Errorf("platform %q (package manager %q) not supported", utils.PlatformLike, utils.PackageManager)
		return h.failPinned(report, updater.Classify(updater.ClassUnknown, err), "")
	}
}

// packageHostNote goes into the report detail when the console sent artifact
// pins to a host that installs through its package manager.
const packageHostNote = "digest not applicable on package-managed host"

// failPinned reports a failed attempt and returns the command result.
func (h *SystemHandler) failPinned(report updater.Report, err error, output string) (int, string, error) {
	report.Outcome = updater.OutcomeFailed
	report.ErrorClass = updater.ClassOf(err)
	if report.Detail != "" {
		report.Detail += "; " + err.Error()
	} else {
		report.Detail = err.Error()
	}
	updater.SendReport(h.apiSession, report)

	msg := fmt.Sprintf("Upgrade to %s failed (%s): %v", report.ToVersion, report.ErrorClass, err)
	if output = strings.TrimRight(output, "\n"); output != "" {
		msg = output + "\n\n" + msg
	}
	log.Error().Str("error_class", string(report.ErrorClass)).Err(err).Msg("Pinned upgrade failed.")
	return 1, msg, err
}

func (h *SystemHandler) pinnedSelfUpdate(ctx context.Context, target *common.UpgradeTarget, tag string, report updater.Report) (int, string, error) {
	req := updater.PinnedRequest{
		TargetVersion:  tag,
		ArtifactURL:    target.ArtifactURL,
		ArtifactDigest: target.ArtifactDigest,
		ChecksumsURL:   target.ChecksumsURL,
		SignatureURL:   target.SignatureURL,
		AttemptID:      target.AttemptID,
		FromVersion:    report.FromVersion,
		HealthGrace:    target.HealthGracePeriod,
	}
	if err := h.pinnedUpdateFn(ctx, req, updater.Options{ServiceManager: h.serviceManager}); err != nil {
		if errors.Is(err, updater.ErrSelfUpdateInProgress) {
			return 0, "Self-update already in progress.", nil
		}
		return h.failPinned(report, err, "")
	}
	return h.restartIntoUpgrade(tag, true)
}

// restartIntoUpgrade restarts the agent after a pinned swap. The service
// manager does it from outside the process, so a new binary that cannot start
// is not re-executed in place; the marker and guard are already in place, so
// the attempt's outcome is reported by the process that comes up next.
//
// Without a service manager the restart falls back to the in-process one when
// inProcessFallback is set. A package install does not set it: its own
// maintainer scripts restart the agent on such hosts.
func (h *SystemHandler) restartIntoUpgrade(tag string, inProcessFallback bool) (int, string, error) {
	err := h.serviceManager.ScheduleRestart(updater.RestartDelay)
	if err == nil {
		return 0, fmt.Sprintf("Updated to %s. Restarting through the service manager in %s...", tag, updater.RestartDelay), nil
	}
	if errors.Is(err, updater.ErrNoServiceManager) && !inProcessFallback {
		return 0, fmt.Sprintf("Updated to %s. The package scripts restart the agent.", tag), nil
	}
	log.Warn().Err(err).Msg("Service manager could not schedule the restart; restarting in process.")
	if err := h.scheduleDelayedAction(delayedActionDelay, func(_ context.Context) {
		h.wsClient.Restart()
	}); err != nil {
		updater.ReleaseSelfUpdateLatch()
		log.Error().Err(err).Msg("Failed to schedule the restart after a pinned upgrade. The upgrade guard restores the previous version if the agent is not restarted.")
		return 1, fmt.Sprintf("Updated to %s, but the restart could not be scheduled: %v. Please restart alpamon manually.", tag, err), err
	}
	return 0, fmt.Sprintf("Updated to %s. Restarting...", tag), nil
}

// pinnedPackageUpgrade installs report.ToVersion through the package manager
// and confirms it against the package database afterwards. The intent marker
// and guard are in place before the install, and roll back with a pinned
// reinstall of the outgoing version.
func (h *SystemHandler) pinnedPackageUpgrade(ctx context.Context, report updater.Report, packageProxy string, grace time.Duration) (int, string, error) {
	target := report.ToVersion
	env := packageProxyEnv(packageProxy)

	previous := h.installedAlpamonVersion(ctx)
	if !updater.PackageVersionRe.MatchString(previous) {
		err := fmt.Errorf("the package database does not report a usable installed alpamon version (%q), so a rollback would be impossible", previous)
		return h.failPinned(report, updater.Classify(updater.ClassPackageManager, err), "")
	}
	marker := &updater.PendingUpgrade{
		AttemptID:              report.AttemptID,
		FromVersion:            report.FromVersion,
		ToVersion:              target,
		Method:                 updater.MethodPackage,
		PackageManager:         utils.PackageManager,
		PreviousPackageVersion: previous,
		Note:                   report.Detail,
	}
	// The install is bounded by the command timeout; the deadline and the
	// guard count from its end, and are re-armed once it has finished.
	abort, err := updater.BeginTransition(marker, h.serviceManager, common.UpgradeTimeout, updater.ClampHealthGrace(grace), h.now())
	if err != nil {
		return h.failPinned(report, updater.Classify(updater.ClassUnknown, err), "")
	}

	output, err := h.installPinnedPackage(ctx, target, env)
	installed := h.installedAlpamonVersion(ctx)
	if err == nil && !packageVersionMatches(installed, target) {
		err = fmt.Errorf("package database reports alpamon %q after installing %s", installed, target)
	}
	if err != nil {
		output = h.undoPackageChange(ctx, marker, installed, env, abort, output)
		return h.failPinned(report, updater.Classify(updater.ClassPackageManager, err), output)
	}

	if err := updater.Rearm(marker, h.serviceManager, updater.ClampHealthGrace(grace), h.now()); err != nil {
		// Rearm put the marker back as it was, so the first guard, still
		// scheduled, keeps covering the attempt.
		log.Warn().Err(err).Msg("Failed to re-arm the upgrade guard after the install.")
	}

	// The package's own upgrade restart runs minutes later and would cut the
	// health check short; the service-manager restart below replaces it.
	if hasSystemd() {
		_, _, _ = h.Executor.RunAsUser(ctx, "root", "systemctl", "stop", "alpamon-restart.timer")
	}
	exitCode, msg, err := h.restartIntoUpgrade("v"+target, false)
	return exitCode, strings.TrimRight(output, "\n") + fmt.Sprintf("\n\nInstalled alpamon %s. ", installed) + msg, err
}

// undoPackageChange handles a failed pinned install. When the package
// database still reports the previous version nothing changed, and the
// marker and guard are simply removed. Otherwise the package did change
// (a failing maintainer script, an unexpected version), so the previous
// version is reinstalled at once; if that fails too, the marker and guard
// stay for the guard to retry and the restored agent to report.
func (h *SystemHandler) undoPackageChange(ctx context.Context, marker *updater.PendingUpgrade, installed string, env map[string]string, abort func(), output string) string {
	previous := marker.PreviousPackageVersion
	if installed == previous {
		abort()
		return output
	}
	// Stand the guard down first so the two never run the package manager
	// at once; one that already started is waited out and left to finish.
	switch h.serviceManager.DisarmGuard(marker.GuardUnit) {
	case updater.GuardRestored:
		return output + "\nThe upgrade guard has already reinstalled the previous version."
	case updater.GuardRunning:
		return output + "\nThe upgrade guard is still reinstalling the previous version."
	}
	argv, err := updater.PackageRollbackCommand(utils.PackageManager, previous, installed)
	if err == nil {
		var code int
		var out string
		code, out, err = h.Executor.Exec(ctx, argv, "root", "root", env, 0)
		output = strings.TrimRight(output, "\n") + "\n\n" + out
		if code != 0 && err == nil {
			err = fmt.Errorf("exited %d", code)
		}
	}
	if err == nil && h.installedAlpamonVersion(ctx) == previous {
		abort()
		return output + fmt.Sprintf("\nReinstalled the previous version %s.", previous)
	}
	log.Error().Err(err).Str("previous", previous).Msg("Could not reinstall the previous version; arming the upgrade guard to retry it.")
	if rerr := updater.Rearm(marker, h.serviceManager, 0, h.now()); rerr != nil || marker.GuardUnit == "" {
		// No guard covers the attempt now; restart so the next start finds
		// the marker and settles it (a version other than the target and
		// the previous one reports the attempt failed).
		log.Error().Err(rerr).Msg("No upgrade guard is armed; restarting so the next start settles the attempt.")
		if serr := h.serviceManager.ScheduleRestart(updater.RestartDelay); serr != nil {
			_ = h.scheduleDelayedAction(delayedActionDelay, func(_ context.Context) { h.wsClient.Restart() })
		}
	}
	return output + fmt.Sprintf("\nCould not reinstall the previous version %s; the upgrade guard retries it.", previous)
}

// installPinnedPackage runs the version-pinned install for the host's package
// manager and returns its output. Arguments are passed without a shell.
func (h *SystemHandler) installPinnedPackage(ctx context.Context, target string, env map[string]string) (string, error) {
	run := func(args ...string) (int, string, error) {
		return retryWhileZypperLocked(ctx, func() (int, string, error) {
			return h.Executor.Exec(ctx, args, "root", "root", env, 0)
		})
	}

	switch utils.PackageManager {
	case utils.PkgApt:
		if code, out, err := run("apt-get", "update", "-y", "-o", "Acquire::Retries=3"); code != 0 {
			return out, commandFailed("apt-get update", code, err)
		}
		code, out, err := run("apt-cache", "madison", "alpamon")
		if code != 0 {
			return out, commandFailed("apt-cache madison", code, err)
		}
		exact := pickDebVersion(out, target)
		if exact == "" {
			return out, fmt.Errorf("the configured repositories do not carry alpamon %s", target)
		}
		code, out, err = run("apt-get", "install", "-y", "--allow-downgrades", "-o", "Acquire::Retries=3", "alpamon="+exact)
		if code != 0 {
			return out, commandFailed("apt-get install", code, err)
		}
		return out, nil

	case utils.PkgYum:
		verb := "install"
		if cur := h.installedAlpamonVersion(ctx); cur != "" && updater.CompareVersions(target, cur) < 0 {
			verb = "downgrade"
		}
		code, out, err := run("yum", verb, "-y", "alpamon-"+target)
		if code != 0 {
			return out, commandFailed("yum "+verb, code, err)
		}
		return out, nil

	case utils.PkgZypper:
		refresh := []string{"zypper", "--non-interactive", "refresh"}
		scoped := false
		if alias := h.resolveZypperAlpamonRepo(ctx); alias != "" {
			refresh = append(refresh, alias)
			scoped = true
		}
		if code, out, err := run(refresh...); code != 0 {
			return withZypperHint(code, out), commandFailed("zypper refresh", code, err)
		}
		code, out, err := run("zypper", "--non-interactive", "install", "--oldpackage", "alpamon="+target)
		code, err = normalizeZypperExit(code, err, scoped)
		if code != 0 {
			return withZypperHint(code, out), commandFailed("zypper install", code, err)
		}
		return out, nil
	}
	return "", fmt.Errorf("package manager %q has no pinned install", utils.PackageManager)
}

func commandFailed(what string, code int, err error) error {
	if err != nil {
		return fmt.Errorf("%s exited %d: %w", what, code, err)
	}
	return fmt.Errorf("%s exited %d", what, code)
}

// installedAlpamonVersion asks the package database for the installed
// alpamon version, or "" when it cannot tell.
func (h *SystemHandler) installedAlpamonVersion(ctx context.Context) string {
	var code int
	var out string
	var err error
	if utils.PackageManager == utils.PkgApt {
		code, out, err = h.Executor.RunAsUser(ctx, "root", "dpkg-query", "-W", "-f=${Version}", "alpamon")
	} else {
		code, out, err = h.Executor.RunAsUser(ctx, "root", "rpm", "-q", "--qf", "%{VERSION}", "alpamon")
	}
	if err != nil || code != 0 {
		return ""
	}
	return strings.TrimSpace(out)
}

// pickDebVersion returns the exact version string `apt-cache madison` lists
// for target: the bare version or one carrying a Debian revision, with or
// without an epoch.
func pickDebVersion(madison, target string) string {
	for line := range strings.SplitSeq(madison, "\n") {
		fields := strings.Split(line, "|")
		if len(fields) < 2 || strings.TrimSpace(fields[0]) != "alpamon" {
			continue
		}
		v := strings.TrimSpace(fields[1])
		if updater.PackageVersionRe.MatchString(v) && packageVersionMatches(v, target) {
			return v
		}
	}
	return ""
}

// packageVersionMatches reports whether a package database version names the
// target release, ignoring an epoch and a packaging revision.
func packageVersionMatches(installed, target string) bool {
	if installed == "" {
		return false
	}
	if i := strings.Index(installed, ":"); i >= 0 {
		installed = installed[i+1:]
	}
	return installed == target || strings.HasPrefix(installed, target+"-")
}
