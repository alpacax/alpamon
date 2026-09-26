package system

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/alpacax/alpamon/v2/pkg/executor/handlers/common"
	"github.com/alpacax/alpamon/v2/pkg/updater"
	"github.com/alpacax/alpamon/v2/pkg/utils"
	"github.com/alpacax/alpamon/v2/pkg/version"
	"github.com/rs/zerolog/log"
)

// packageVersionRe bounds what a repository may hand back as a package
// version before it is placed in an install argument.
var packageVersionRe = regexp.MustCompile(`^[0-9A-Za-z.+~:-]+$`)

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

	if sameVersion(version.Version, tag) {
		report.Outcome = updater.OutcomeSucceeded
		report.Detail = "already running the target version"
		updater.SendReport(h.apiSession, report)
		return 0, fmt.Sprintf("Already running %s.", tag), nil
	}

	log.Info().Str("target", tag).Str("attempt_id", target.AttemptID).Msg("Pinned upgrade requested.")

	switch utils.PackageManager {
	case utils.PkgApt, utils.PkgYum, utils.PkgZypper:
		return h.pinnedPackageUpgrade(ctx, report, packageProxy)
	case utils.PkgBrew, utils.PkgNone:
		return h.pinnedSelfUpdate(ctx, target, tag, report)
	default:
		err := fmt.Errorf("platform %q (package manager %q) not supported", utils.PlatformLike, utils.PackageManager)
		return h.failPinned(report, updater.Classify(updater.ClassUnknown, err), "")
	}
}

// failPinned reports a failed attempt and returns the command result.
func (h *SystemHandler) failPinned(report updater.Report, err error, output string) (int, string, error) {
	report.Outcome = updater.OutcomeFailed
	report.ErrorClass = updater.ClassOf(err)
	report.Detail = err.Error()
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
	}
	if err := h.pinnedUpdateFn(ctx, req, updater.Options{}); err != nil {
		if errors.Is(err, updater.ErrSelfUpdateInProgress) {
			return 0, "Self-update already in progress.", nil
		}
		return h.failPinned(report, err, "")
	}

	if err := h.scheduleDelayedAction(delayedActionDelay, func(_ context.Context) {
		h.wsClient.Restart()
	}); err != nil {
		updater.ReleaseSelfUpdateLatch()
		return h.failPinned(report, updater.Classify(updater.ClassUnknown,
			fmt.Errorf("updated to %s, but the restart could not be scheduled; restart alpamon manually: %w", tag, err)), "")
	}
	return 0, fmt.Sprintf("Updated to %s. Restarting...", tag), nil
}

// pinnedPackageUpgrade installs report.ToVersion through the package manager
// and confirms it against the package database afterwards.
func (h *SystemHandler) pinnedPackageUpgrade(ctx context.Context, report updater.Report, packageProxy string) (int, string, error) {
	target := report.ToVersion
	env := packageProxyEnv(packageProxy)

	output, err := h.installPinnedPackage(ctx, target, env)
	if err != nil {
		return h.failPinned(report, updater.Classify(updater.ClassPackageManager, err), output)
	}

	installed := h.installedAlpamonVersion(ctx)
	if !packageVersionMatches(installed, target) {
		err := fmt.Errorf("package database reports alpamon %q after installing %s", installed, target)
		return h.failPinned(report, updater.Classify(updater.ClassPackageManager, err), output)
	}
	return 0, strings.TrimRight(output, "\n") + fmt.Sprintf("\n\nInstalled alpamon %s.", installed), nil
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
		if cur := h.installedAlpamonVersion(ctx); cur != "" && compareVersions(target, cur) < 0 {
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
		if packageVersionRe.MatchString(v) && packageVersionMatches(v, target) {
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

// compareVersions orders two "X.Y.Z" versions numerically, ignoring any
// pre-release or packaging suffix. It returns -1, 0 or 1.
func compareVersions(a, b string) int {
	pa, pb := versionParts(a), versionParts(b)
	for i := range pa {
		switch {
		case pa[i] < pb[i]:
			return -1
		case pa[i] > pb[i]:
			return 1
		}
	}
	return 0
}

func versionParts(v string) [3]int {
	var out [3]int
	v = strings.TrimPrefix(v, "v")
	if i := strings.IndexAny(v, "-+~"); i >= 0 {
		v = v[:i]
	}
	for i, p := range strings.SplitN(v, ".", 3) {
		out[i], _ = strconv.Atoi(p)
	}
	return out
}
