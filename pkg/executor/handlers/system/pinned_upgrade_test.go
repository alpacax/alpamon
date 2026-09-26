package system

import (
	"context"
	"errors"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/alpacax/alpamon/v2/internal/pool"
	"github.com/alpacax/alpamon/v2/pkg/agent"
	"github.com/alpacax/alpamon/v2/pkg/executor/handlers/common"
	"github.com/alpacax/alpamon/v2/pkg/updater"
	"github.com/alpacax/alpamon/v2/pkg/utils"
	"github.com/alpacax/alpamon/v2/pkg/version"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const madisonOutput = `   alpamon |    2.6.0 | https://packages.example/any any/main amd64 Packages
   alpamon |    2.5.0 | https://packages.example/any any/main amd64 Packages
`

type pinnedHarness struct {
	exec     *common.MockCommandExecutor
	ws       *MockWSClient
	versions *MockVersionResolver
	api      *MockAPISession
	sm       *fakeServiceManager
	handler  *SystemHandler
}

// fakeServiceManager records what would have been scheduled.
type fakeServiceManager struct {
	restarts   []time.Duration
	guards     []string
	disarmed   []string
	restartErr error
}

func (f *fakeServiceManager) ScheduleRestart(d time.Duration) error {
	if f.restartErr != nil {
		return f.restartErr
	}
	f.restarts = append(f.restarts, d)
	return nil
}

func (f *fakeServiceManager) ArmGuard(unit string, _ time.Duration, _ string) error {
	f.guards = append(f.guards, unit)
	return nil
}

func (f *fakeServiceManager) DisarmGuard(unit string) { f.disarmed = append(f.disarmed, unit) }

// markerCheckingExecutor records whether the intent marker existed when the
// package install ran.
type markerCheckingExecutor struct {
	*common.MockCommandExecutor
	markerAtInstall *updater.PendingUpgrade
}

func (e *markerCheckingExecutor) Exec(ctx context.Context, args []string, username, groupname string, env map[string]string, timeout time.Duration) (int, string, error) {
	if len(args) > 1 && args[0] == "apt-get" && args[1] == "install" {
		e.markerAtInstall, _ = updater.LoadPending()
	}
	return e.MockCommandExecutor.Exec(ctx, args, username, groupname, env, timeout)
}

func newPinnedHarness(t *testing.T, pkgManager string) *pinnedHarness {
	t.Helper()
	ctxManager := agent.NewContextManager()
	workerPool := pool.NewPool(2, 10)
	t.Cleanup(func() { _ = workerPool.Shutdown(poolDrainWait) })
	t.Cleanup(ctxManager.Shutdown)

	t.Cleanup(updater.OverrideMarkerDir(t.TempDir()))
	origHasSystemd := hasSystemd
	hasSystemd = func() bool { return true }
	t.Cleanup(func() { hasSystemd = origHasSystemd })

	h := &pinnedHarness{
		exec:     common.NewMockCommandExecutor(t),
		ws:       &MockWSClient{},
		versions: &MockVersionResolver{LatestVersion: "v9.9.9"},
		api:      &MockAPISession{},
		sm:       &fakeServiceManager{},
	}
	h.handler = NewSystemHandler(h.exec, h.ws, ctxManager, workerPool, h.versions, h.api)
	h.handler.serviceManager = h.sm
	h.handler.selfUpdateFn = func(context.Context, string, updater.Options) error {
		t.Error("the legacy self-update must not run for a pinned target")
		return nil
	}
	h.handler.pinnedUpdateFn = func(context.Context, updater.PinnedRequest, updater.Options) error {
		t.Error("the tarball path must not run on a package-managed host")
		return nil
	}
	setPackageManagerAndID(t, pkgManager, "")
	return h
}

func (h *pinnedHarness) upgrade(t *testing.T, target *common.UpgradeTarget) (int, string, error) {
	t.Helper()
	return h.handler.Execute(context.Background(), common.Upgrade.String(), &common.CommandArgs{Upgrade: target})
}

func (h *pinnedHarness) ran(program string, args ...string) bool {
	want := strings.Join(append([]string{program}, args...), " ")
	for _, c := range h.exec.GetExecutedCommands() {
		if strings.Join(append([]string{c.Name}, c.Args...), " ") == want {
			return true
		}
	}
	return false
}

func (h *pinnedHarness) lastReport(t *testing.T) updater.Report {
	t.Helper()
	posts := h.api.posts()
	require.NotEmpty(t, posts, "an upgrade report must be posted")
	last := posts[len(posts)-1]
	assert.Equal(t, updater.ReportURL, last.URL)
	r, ok := last.Body.(updater.Report)
	require.True(t, ok, "report body is %T", last.Body)
	return r
}

// TestSystemHandler_Upgrade_LegacyPathUnchanged pins the path every existing
// server drives: no target version means the same package-manager command,
// the GitHub lookup, and no upgrade report.
func TestSystemHandler_Upgrade_LegacyPathUnchanged(t *testing.T) {
	h := newPinnedHarness(t, utils.PkgApt)

	exitCode, _, err := h.handler.Execute(context.Background(), common.Upgrade.String(), &common.CommandArgs{})
	require.NoError(t, err)
	assert.Equal(t, 0, exitCode)

	assert.Equal(t, 1, h.versions.LatestCalls, "the legacy path still asks GitHub for the latest release")
	shell := findExecutedShell(h.exec)
	require.NotNil(t, shell)
	assert.Equal(t, []string{"-c", "apt-get update -y -o Acquire::Retries=3 && apt-get install --only-upgrade alpamon -y -o Acquire::Retries=3"}, shell.Args)
	assert.Len(t, h.exec.GetExecutedCommands(), 1, "nothing but the legacy shell runs")
	assert.Empty(t, h.api.posts(), "the legacy path sends no upgrade report")
}

func TestSystemHandler_Upgrade_LegacySelfUpdateUnchanged(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := newPinnedHarness(t, utils.PkgBrew)
		var got string
		h.handler.selfUpdateFn = func(_ context.Context, v string, opts updater.Options) error {
			got = v
			assert.Equal(t, updater.Options{}, opts)
			return nil
		}

		exitCode, output, err := h.handler.Execute(context.Background(), common.Upgrade.String(), &common.CommandArgs{})
		require.NoError(t, err)
		assert.Equal(t, 0, exitCode)
		assert.Equal(t, "Updated to v9.9.9. Restarting...", output)
		assert.Equal(t, "v9.9.9", got)
		assert.Empty(t, h.api.posts())
	})
}

func TestSystemHandler_PinnedUpgrade_Apt(t *testing.T) {
	h := newPinnedHarness(t, utils.PkgApt)
	h.exec.SetResult("apt-cache madison alpamon", 0, madisonOutput, nil)
	h.exec.SetResult("dpkg-query -W -f=${Version} alpamon", 0, "2.5.0", nil)

	exitCode, output, err := h.upgrade(t, &common.UpgradeTarget{TargetVersion: "2.5.0", AttemptID: "att-1"})
	require.NoError(t, err)
	assert.Equal(t, 0, exitCode, output)
	assert.Contains(t, output, "Installed alpamon 2.5.0")

	assert.Zero(t, h.versions.LatestCalls, "a pinned upgrade does not ask for the latest release")
	assert.True(t, h.ran("apt-get", "install", "-y", "--allow-downgrades", "-o", "Acquire::Retries=3", "alpamon=2.5.0"))
	assert.Nil(t, findExecutedShell(h.exec), "the pinned install runs without a shell")

	assert.True(t, h.ran("systemctl", "stop", "alpamon-restart.timer"), "the package's own delayed restart is replaced")
	assert.Equal(t, []time.Duration{updater.RestartDelay}, h.sm.restarts, "restarted through the service manager")
	assert.False(t, h.ws.RestartCalled, "not re-executed in process")
	assert.Len(t, h.sm.guards, 1)
	assert.Empty(t, h.api.posts(), "success is reported by the process that confirms its health")
}

func TestSystemHandler_PinnedUpgrade_MarkerAndGuardPrecedeTheInstall(t *testing.T) {
	h := newPinnedHarness(t, utils.PkgApt)
	exec := &markerCheckingExecutor{MockCommandExecutor: h.exec}
	h.handler.Executor = exec
	h.exec.SetResult("apt-cache madison alpamon", 0, madisonOutput, nil)
	// The mock answers every dpkg-query alike: the version before the install
	// is what the rollback reinstalls.
	h.exec.SetResult("dpkg-query -W -f=${Version} alpamon", 0, "2.5.0", nil)

	exitCode, output, err := h.upgrade(t, &common.UpgradeTarget{TargetVersion: "2.5.0", AttemptID: "att-9", HealthGracePeriod: 3 * time.Minute})
	require.NoError(t, err)
	require.Equal(t, 0, exitCode, output)

	require.NotNil(t, exec.markerAtInstall, "the marker is on disk before the package changes")
	m := exec.markerAtInstall
	assert.Equal(t, "att-9", m.AttemptID)
	assert.Equal(t, updater.MethodPackage, m.Method)
	assert.Equal(t, utils.PkgApt, m.PackageManager)
	assert.Equal(t, "2.5.0", m.PreviousPackageVersion)
	assert.Equal(t, m.StartedAt.Add(updater.RestartDelay+3*time.Minute), m.Deadline)
	assert.Equal(t, []string{m.GuardUnit}, h.sm.guards, "the guard is armed before the install")
}

func TestSystemHandler_PinnedUpgrade_FailureClearsMarkerAndGuard(t *testing.T) {
	h := newPinnedHarness(t, utils.PkgApt)
	h.exec.SetResult("dpkg-query -W -f=${Version} alpamon", 0, "2.4.0", nil)
	h.exec.SetResult("apt-cache madison alpamon", 0, "", nil)

	exitCode, _, err := h.upgrade(t, &common.UpgradeTarget{TargetVersion: "2.5.0"})
	require.Error(t, err)
	assert.Equal(t, 1, exitCode)

	marker, err := updater.LoadPending()
	require.NoError(t, err)
	assert.Nil(t, marker)
	require.Len(t, h.sm.guards, 1)
	assert.Equal(t, h.sm.guards, h.sm.disarmed)
	assert.Empty(t, h.sm.restarts)
}

func TestSystemHandler_PinnedUpgrade_NeedsTheInstalledVersionToRollBack(t *testing.T) {
	h := newPinnedHarness(t, utils.PkgApt)
	h.exec.SetResult("dpkg-query -W -f=${Version} alpamon", 1, "", errors.New("not installed"))

	exitCode, _, err := h.upgrade(t, &common.UpgradeTarget{TargetVersion: "2.5.0", AttemptID: "att-10"})
	require.Error(t, err)
	assert.Equal(t, 1, exitCode)
	assert.Equal(t, updater.ClassPackageManager, h.lastReport(t).ErrorClass)
	assert.Empty(t, h.sm.guards)
	assert.False(t, h.exec.Invoked("apt-get"))
}

func TestSystemHandler_PinnedUpgrade_RefusesWhileAnUpgradeIsPending(t *testing.T) {
	h := newPinnedHarness(t, utils.PkgApt)
	h.exec.SetResult("dpkg-query -W -f=${Version} alpamon", 0, "2.4.0", nil)
	require.NoError(t, updater.WritePending(&updater.PendingUpgrade{AttemptID: "earlier", ToVersion: "2.4.9"}))

	exitCode, _, err := h.upgrade(t, &common.UpgradeTarget{TargetVersion: "2.5.0"})
	require.ErrorIs(t, err, updater.ErrUpgradePending)
	assert.Equal(t, 1, exitCode)
	assert.False(t, h.exec.Invoked("apt-get"))
}

func TestSystemHandler_PinnedUpgrade_PackageScriptsRestartWithoutServiceManager(t *testing.T) {
	h := newPinnedHarness(t, utils.PkgApt)
	h.sm.restartErr = updater.ErrNoServiceManager
	h.exec.SetResult("apt-cache madison alpamon", 0, madisonOutput, nil)
	h.exec.SetResult("dpkg-query -W -f=${Version} alpamon", 0, "2.5.0", nil)

	exitCode, output, err := h.upgrade(t, &common.UpgradeTarget{TargetVersion: "2.5.0"})
	require.NoError(t, err)
	assert.Equal(t, 0, exitCode)
	assert.Contains(t, output, "package scripts restart")
	assert.False(t, h.ws.RestartCalled)
}

func TestSystemHandler_PinnedUpgrade_AptWithoutTargetFails(t *testing.T) {
	h := newPinnedHarness(t, utils.PkgApt)
	h.exec.SetResult("apt-cache madison alpamon", 0, "   alpamon |    2.6.0 | https://packages.example Packages\n", nil)

	exitCode, output, err := h.upgrade(t, &common.UpgradeTarget{TargetVersion: "v2.5.0", AttemptID: "att-2"})
	require.Error(t, err)
	assert.Equal(t, 1, exitCode)
	assert.Contains(t, output, "package_manager")
	for _, c := range h.exec.GetExecutedCommands() {
		assert.False(t, c.Name == "apt-get" && len(c.Args) > 0 && c.Args[0] == "install",
			"nothing may be installed in the target's place: %v", c.Args)
	}

	r := h.lastReport(t)
	assert.Equal(t, updater.Report{
		AttemptID:   "att-2",
		FromVersion: "dev",
		ToVersion:   "2.5.0",
		Outcome:     updater.OutcomeFailed,
		ErrorClass:  updater.ClassPackageManager,
		Detail:      r.Detail,
	}, r)
	assert.Contains(t, r.Detail, "do not carry alpamon 2.5.0")
}

func TestSystemHandler_PinnedUpgrade_PackageDatabaseDisagrees(t *testing.T) {
	h := newPinnedHarness(t, utils.PkgApt)
	h.exec.SetResult("apt-cache madison alpamon", 0, madisonOutput, nil)
	h.exec.SetResult("dpkg-query -W -f=${Version} alpamon", 0, "2.6.0", nil)

	exitCode, _, err := h.upgrade(t, &common.UpgradeTarget{TargetVersion: "2.5.0", AttemptID: "att-3"})
	require.Error(t, err)
	assert.Equal(t, 1, exitCode)
	assert.Equal(t, updater.ClassPackageManager, h.lastReport(t).ErrorClass)
}

func TestSystemHandler_PinnedUpgrade_InstallFailure(t *testing.T) {
	h := newPinnedHarness(t, utils.PkgApt)
	h.exec.SetResult("apt-cache madison alpamon", 0, madisonOutput, nil)
	h.exec.SetResult("apt-get install -y --allow-downgrades -o Acquire::Retries=3 alpamon=2.5.0", 100, "E: broken", errors.New("exit status 100"))

	exitCode, output, err := h.upgrade(t, &common.UpgradeTarget{TargetVersion: "2.5.0", AttemptID: "att-4"})
	require.Error(t, err)
	assert.Equal(t, 1, exitCode)
	assert.Contains(t, output, "E: broken")
	assert.Equal(t, updater.ClassPackageManager, h.lastReport(t).ErrorClass)
}

func TestSystemHandler_PinnedUpgrade_Yum(t *testing.T) {
	for _, tc := range []struct {
		installed, verb string
	}{
		{"2.4.0", "install"},
		{"2.6.0", "downgrade"},
	} {
		t.Run(tc.verb, func(t *testing.T) {
			h := newPinnedHarness(t, utils.PkgYum)
			// The mock gives the same rpm answer before and after the install,
			// so only the verb is asserted; the check afterwards is covered by
			// the apt tests.
			h.exec.SetResult("rpm -q --qf %{VERSION} alpamon", 0, tc.installed, nil)

			_, _, _ = h.upgrade(t, &common.UpgradeTarget{TargetVersion: "2.5.0"})
			assert.True(t, h.ran("yum", tc.verb, "-y", "alpamon-2.5.0"))
		})
	}
}

func TestSystemHandler_PinnedUpgrade_Zypper(t *testing.T) {
	h := newPinnedHarness(t, utils.PkgZypper)
	h.exec.SetResult("rpm -q --qf %{VERSION} alpamon", 0, "2.5.0", nil)

	exitCode, output, err := h.upgrade(t, &common.UpgradeTarget{TargetVersion: "2.5.0"})
	require.NoError(t, err)
	assert.Equal(t, 0, exitCode, output)
	assert.True(t, h.ran("zypper", "--non-interactive", "refresh"))
	assert.True(t, h.ran("zypper", "--non-interactive", "install", "--oldpackage", "alpamon=2.5.0"))
}

func TestSystemHandler_PinnedUpgrade_SelfUpdate(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := newPinnedHarness(t, utils.PkgBrew)
		var got updater.PinnedRequest
		var gotOpts updater.Options
		h.handler.pinnedUpdateFn = func(_ context.Context, req updater.PinnedRequest, opts updater.Options) error {
			got, gotOpts = req, opts
			return nil
		}
		target := &common.UpgradeTarget{
			AttemptID:         "att-8",
			HealthGracePeriod: 4 * time.Minute,
			TargetVersion:     "2.5.0",
			ArtifactURL:       "https://mirror.example/a.tar.gz",
			ArtifactDigest:    "sha256:" + strings.Repeat("a", 64),
			ChecksumsURL:      "https://mirror.example/sums",
			SignatureURL:      "https://mirror.example/sums.sig",
		}

		exitCode, output, err := h.upgrade(t, target)
		require.NoError(t, err)
		assert.Equal(t, 0, exitCode, output)
		assert.Equal(t, updater.PinnedRequest{
			TargetVersion:  "v2.5.0",
			ArtifactURL:    target.ArtifactURL,
			ArtifactDigest: target.ArtifactDigest,
			ChecksumsURL:   target.ChecksumsURL,
			SignatureURL:   target.SignatureURL,
			AttemptID:      "att-8",
			FromVersion:    "dev",
			HealthGrace:    4 * time.Minute,
		}, got)
		assert.Same(t, h.sm, gotOpts.ServiceManager, "the updater arms its guard with the handler's service manager")
		assert.Zero(t, h.versions.LatestCalls)

		assert.Equal(t, []time.Duration{updater.RestartDelay}, h.sm.restarts)
		time.Sleep(2 * delayedActionDelay)
		synctest.Wait()
		assert.False(t, h.ws.RestartCalled, "restarted from outside the process")
	})
}

func TestSystemHandler_PinnedUpgrade_SelfUpdateRestartsInProcessWithoutServiceManager(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := newPinnedHarness(t, utils.PkgBrew)
		h.sm.restartErr = updater.ErrNoServiceManager
		h.handler.pinnedUpdateFn = func(context.Context, updater.PinnedRequest, updater.Options) error { return nil }

		exitCode, _, err := h.upgrade(t, &common.UpgradeTarget{TargetVersion: "2.5.0"})
		require.NoError(t, err)
		assert.Equal(t, 0, exitCode)

		time.Sleep(2 * delayedActionDelay)
		synctest.Wait()
		assert.True(t, h.ws.RestartCalled)
	})
}

func TestSystemHandler_PinnedUpgrade_SelfUpdateFailureIsReported(t *testing.T) {
	h := newPinnedHarness(t, utils.PkgNone)
	h.handler.pinnedUpdateFn = func(context.Context, updater.PinnedRequest, updater.Options) error {
		return updater.Classify(updater.ClassSignatureInvalid, updater.ErrNoTrustedKeys)
	}

	exitCode, output, err := h.upgrade(t, &common.UpgradeTarget{TargetVersion: "2.5.0", AttemptID: "att-5"})
	require.Error(t, err)
	assert.Equal(t, 1, exitCode)
	assert.Contains(t, output, "signature_invalid")
	assert.False(t, h.ws.RestartCalled)
	assert.Equal(t, updater.ClassSignatureInvalid, h.lastReport(t).ErrorClass)
}

func TestSystemHandler_PinnedUpgrade_InvalidTarget(t *testing.T) {
	h := newPinnedHarness(t, utils.PkgApt)

	exitCode, _, err := h.upgrade(t, &common.UpgradeTarget{TargetVersion: "latest", AttemptID: "att-6"})
	require.Error(t, err)
	assert.Equal(t, 1, exitCode)
	assert.Equal(t, updater.ClassUnknown, h.lastReport(t).ErrorClass)
	assert.Empty(t, h.exec.GetExecutedCommands())
}

func TestSystemHandler_PinnedUpgrade_AlreadyAtTarget(t *testing.T) {
	h := newPinnedHarness(t, utils.PkgApt)
	original := version.Version
	version.Version = "2.5.0"
	t.Cleanup(func() { version.Version = original })

	exitCode, output, err := h.upgrade(t, &common.UpgradeTarget{TargetVersion: "v2.5.0", AttemptID: "att-7"})
	require.NoError(t, err)
	assert.Equal(t, 0, exitCode)
	assert.Contains(t, output, "Already running")
	assert.Empty(t, h.exec.GetExecutedCommands())
	r := h.lastReport(t)
	assert.Equal(t, updater.OutcomeSucceeded, r.Outcome)
	assert.Equal(t, "2.5.0", r.FromVersion)
}

func TestPickDebVersion(t *testing.T) {
	assert.Equal(t, "2.5.0", pickDebVersion(madisonOutput, "2.5.0"))
	assert.Equal(t, "1:2.5.0-1", pickDebVersion("alpamon | 1:2.5.0-1 | x\n", "2.5.0"))
	assert.Empty(t, pickDebVersion(madisonOutput, "2.5"), "a prefix of another version is not a match")
	assert.Empty(t, pickDebVersion("alpamon-pam | 2.5.0 | x\n", "2.5.0"))
	assert.Empty(t, pickDebVersion("alpamon | 2.5.0 --evil | x\n", "2.5.0"))
}

func TestPackageVersionMatches(t *testing.T) {
	assert.True(t, packageVersionMatches("2.5.0", "2.5.0"))
	assert.True(t, packageVersionMatches("2.5.0-1", "2.5.0"))
	assert.True(t, packageVersionMatches("1:2.5.0", "2.5.0"))
	assert.False(t, packageVersionMatches("2.5.01", "2.5.0"))
	assert.False(t, packageVersionMatches("", "2.5.0"))
}

func TestCompareVersions(t *testing.T) {
	assert.Equal(t, -1, compareVersions("2.5.0", "2.6.0"))
	assert.Equal(t, 1, compareVersions("2.10.0", "2.9.9"))
	assert.Equal(t, 0, compareVersions("v2.5.0", "2.5.0-1"))
}

func TestSystemHandler_PinnedUpgrade_PackageHostSaysPinsDoNotApply(t *testing.T) {
	h := newPinnedHarness(t, utils.PkgApt)
	h.exec.SetResult("apt-cache madison alpamon", 0, "", nil)

	_, _, err := h.upgrade(t, &common.UpgradeTarget{
		TargetVersion:  "2.5.0",
		AttemptID:      "att-12",
		ArtifactDigest: "sha256:" + strings.Repeat("a", 64),
	})
	require.Error(t, err)
	r := h.lastReport(t)
	assert.True(t, strings.HasPrefix(r.Detail, "digest not applicable on package-managed host; "), r.Detail)
}
