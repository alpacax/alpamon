package updater

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/alpacax/alpamon/v2/pkg/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMarker_RoundTrip(t *testing.T) {
	dir := useTempMarkerDir(t)

	got, err := LoadPending()
	require.NoError(t, err)
	assert.Nil(t, got, "no marker means no upgrade in flight")

	want := &PendingUpgrade{
		AttemptID: "att", FromVersion: "2.4.0", ToVersion: "2.5.0", Method: MethodBinary,
		BinaryPath: "/usr/bin/alpamon", RollbackPath: "/usr/bin/alpamon.rollback",
		GuardUnit: "g", StartedAt: time.Unix(100, 0).UTC(), Deadline: time.Unix(400, 0).UTC(),
	}
	require.NoError(t, WritePending(want))
	assert.Equal(t, filepath.Join(dir, "upgrade.pending"), MarkerPath())

	got, err = LoadPending()
	require.NoError(t, err)
	assert.Equal(t, want, got)

	if runtime.GOOS != "windows" {
		info, err := os.Stat(MarkerPath())
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0600), info.Mode().Perm())
	}
	_, err = os.Stat(MarkerPath() + ".tmp")
	assert.ErrorIs(t, err, os.ErrNotExist)

	require.NoError(t, ClearPending())
	require.NoError(t, ClearPending(), "clearing is idempotent")
	_, err = os.Stat(MarkerPath())
	assert.ErrorIs(t, err, os.ErrNotExist)
}

func TestClampHealthGrace(t *testing.T) {
	assert.Equal(t, DefaultHealthGrace, ClampHealthGrace(0))
	assert.Equal(t, minHealthGrace, ClampHealthGrace(time.Second))
	assert.Equal(t, maxHealthGrace, ClampHealthGrace(24*time.Hour))
	assert.Equal(t, 10*time.Minute, ClampHealthGrace(10*time.Minute))
}

func binaryMarker(dir string) *PendingUpgrade {
	return &PendingUpgrade{
		AttemptID: "att", FromVersion: "2.4.0", ToVersion: "2.5.0", Method: MethodBinary,
		BinaryPath: filepath.Join(dir, "alpamon"), RollbackPath: filepath.Join(dir, "alpamon.rollback"),
	}
}

func TestBeginTransition_WritesMarkerThenArmsGuard(t *testing.T) {
	useTempMarkerDir(t)
	sm := &fakeServiceManager{}
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	p := binaryMarker(t.TempDir())

	abort, err := BeginTransition(p, sm, 0, 3*time.Minute, now)
	require.NoError(t, err)
	require.NotNil(t, abort)

	stored, err := LoadPending()
	require.NoError(t, err)
	assert.Equal(t, now, stored.StartedAt)
	assert.Equal(t, now.Add(RestartDelay+3*time.Minute), stored.Deadline)
	assert.NotEmpty(t, stored.GuardUnit)

	_, guards, _ := sm.snapshot()
	require.Len(t, guards, 1)
	assert.Equal(t, stored.GuardUnit, guards[0].unit)
	assert.Equal(t, RestartDelay+3*time.Minute+guardMargin, guards[0].delay, "the guard fires after the deadline")
	assert.Contains(t, guards[0].script, shellQuote(MarkerPath()))
}

func TestBeginTransition_RefusesWhileAnotherIsPending(t *testing.T) {
	useTempMarkerDir(t)
	require.NoError(t, WritePending(&PendingUpgrade{AttemptID: "earlier", ToVersion: "2.5.0", Deadline: time.Now().Add(time.Minute)}))
	sm := &fakeServiceManager{}

	_, err := BeginTransition(binaryMarker(t.TempDir()), sm, 0, time.Minute, time.Now())
	assert.ErrorIs(t, err, ErrUpgradePending)
	_, guards, _ := sm.snapshot()
	assert.Empty(t, guards)
	stored, _ := LoadPending()
	assert.Equal(t, "earlier", stored.AttemptID, "the pending marker is left alone")
}

func TestBeginTransition_DiscardsAStaleMarker(t *testing.T) {
	useTempMarkerDir(t)
	now := time.Now()
	require.NoError(t, WritePending(&PendingUpgrade{AttemptID: "abandoned", GuardUnit: "old-guard", Deadline: now.Add(-staleMarkerAge - time.Minute)}))
	sm := &fakeServiceManager{}

	_, err := BeginTransition(binaryMarker(t.TempDir()), sm, 0, time.Minute, now)
	require.NoError(t, err)
	stored, err := LoadPending()
	require.NoError(t, err)
	assert.Equal(t, "att", stored.AttemptID)
	_, _, disarmed := sm.snapshot()
	assert.Equal(t, []string{"old-guard"}, disarmed)
}

func TestBeginTransition_SettleDelaysDeadlineAndGuard(t *testing.T) {
	useTempMarkerDir(t)
	sm := &fakeServiceManager{}
	now := time.Now()
	p := binaryMarker(t.TempDir())

	_, err := BeginTransition(p, sm, 30*time.Minute, 2*time.Minute, now)
	require.NoError(t, err)
	assert.Equal(t, now.UTC().Add(30*time.Minute+RestartDelay+2*time.Minute), p.Deadline)
	_, guards, _ := sm.snapshot()
	assert.Equal(t, 30*time.Minute+RestartDelay+2*time.Minute+guardMargin, guards[0].delay)

	first := p.GuardUnit
	later := now.Add(10 * time.Minute)
	require.NoError(t, Rearm(p, sm, 2*time.Minute, later))
	assert.Equal(t, later.UTC().Add(RestartDelay+2*time.Minute), p.Deadline)
	assert.NotEqual(t, first, p.GuardUnit)
	_, guards, disarmed := sm.snapshot()
	require.Len(t, guards, 2)
	assert.Equal(t, RestartDelay+2*time.Minute+guardMargin, guards[1].delay)
	assert.Equal(t, []string{first}, disarmed, "the first guard is replaced")
	stored, err := LoadPending()
	require.NoError(t, err)
	assert.Equal(t, p.GuardUnit, stored.GuardUnit)
	assert.Equal(t, p.Deadline, stored.Deadline)
}

func TestBeginTransition_WithoutServiceManager(t *testing.T) {
	useTempMarkerDir(t)
	_, err := BeginTransition(binaryMarker(t.TempDir()), noServiceManager{}, 0, time.Minute, time.Now())
	require.NoError(t, err)
	stored, err := LoadPending()
	require.NoError(t, err)
	assert.Empty(t, stored.GuardUnit, "no guard is recorded when none could be armed")
}

func TestBeginTransition_GuardFailureAborts(t *testing.T) {
	useTempMarkerDir(t)
	sm := &fakeServiceManager{guardErr: errors.New("systemd-run: boom")}

	_, err := BeginTransition(binaryMarker(t.TempDir()), sm, 0, time.Minute, time.Now())
	assert.ErrorContains(t, err, "arm upgrade guard")
	stored, err := LoadPending()
	require.NoError(t, err)
	assert.Nil(t, stored, "a failed guard leaves no marker behind")
}

func TestBeginTransition_AbortUndoesEverything(t *testing.T) {
	useTempMarkerDir(t)
	dir := t.TempDir()
	p := binaryMarker(dir)
	require.NoError(t, os.WriteFile(p.RollbackPath, []byte("old"), 0600))
	sm := &fakeServiceManager{}

	abort, err := BeginTransition(p, sm, 0, time.Minute, time.Now())
	require.NoError(t, err)
	abort()

	stored, err := LoadPending()
	require.NoError(t, err)
	assert.Nil(t, stored)
	_, err = os.Stat(p.RollbackPath)
	assert.ErrorIs(t, err, os.ErrNotExist)
	_, _, disarmed := sm.snapshot()
	assert.Equal(t, []string{p.GuardUnit}, disarmed)
}

func TestStageRollbackCopy(t *testing.T) {
	current := filepath.Join(t.TempDir(), "alpamon")
	require.NoError(t, os.WriteFile(current, []byte("old"), 0755))

	rollback, err := stageRollbackCopy(current)
	require.NoError(t, err)
	assert.Equal(t, current+".rollback", rollback)
	got, err := os.ReadFile(rollback)
	require.NoError(t, err)
	assert.Equal(t, "old", string(got))
	if runtime.GOOS != "windows" {
		info, err := os.Stat(rollback)
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0755), info.Mode().Perm())
	}
}

func TestRestoreBinary(t *testing.T) {
	dir := t.TempDir()
	current, rollback := filepath.Join(dir, "alpamon"), filepath.Join(dir, "alpamon.rollback")
	require.NoError(t, os.WriteFile(current, []byte("new"), 0755))
	require.NoError(t, os.WriteFile(rollback, []byte("old"), 0755))

	require.NoError(t, restoreBinary(rollback, current))
	got, err := os.ReadFile(current)
	require.NoError(t, err)
	assert.Equal(t, "old", string(got))
	_, err = os.Stat(rollback)
	assert.ErrorIs(t, err, os.ErrNotExist)
}

func TestSystemdManager(t *testing.T) {
	t.Run("restart and guard are transient timers", func(t *testing.T) {
		r := &fakeRunner{}
		m := &systemdManager{run: r.run}
		require.NoError(t, m.ScheduleRestart(5*time.Second))
		require.NoError(t, m.ArmGuard("alpamon-upgrade-guard-1", 7*time.Minute, "echo hi"))

		calls := r.snapshot()
		require.Len(t, calls, 2)
		assert.Equal(t, "systemd-run", calls[0][0])
		assert.Equal(t, []string{"--collect", "--on-active=5s", "--timer-property=AccuracySec=1s"}, calls[0][1:4])
		assert.Equal(t, []string{"systemctl", "restart", "alpamon"}, calls[0][len(calls[0])-3:])
		assert.Equal(t, []string{"systemd-run", "--collect", "--on-active=420s", "--timer-property=AccuracySec=1s",
			"--unit", "alpamon-upgrade-guard-1", "/bin/sh", "-c", "echo hi"}, calls[1])
	})

	t.Run("retries without --collect for old systemd", func(t *testing.T) {
		r := &fakeRunner{err: errors.New("unrecognized option '--collect'")}
		m := &systemdManager{run: r.run}
		assert.Error(t, m.ScheduleRestart(time.Second), "both attempts fail with the fake error")
		calls := r.snapshot()
		require.Len(t, calls, 2)
		assert.Equal(t, "--collect", calls[0][1])
		assert.NotContains(t, calls[1], "--collect")
	})

	t.Run("disarm stops the timer", func(t *testing.T) {
		r := &fakeRunner{}
		m := &systemdManager{run: r.run}
		m.DisarmGuard("")
		assert.Empty(t, r.snapshot(), "no unit, nothing to stop")
		m.DisarmGuard("g1")
		assert.Equal(t, []string{"systemctl", "stop", "g1.timer"}, r.snapshot()[0])
	})
}

func TestNoServiceManager(t *testing.T) {
	var sm ServiceManager = noServiceManager{}
	assert.ErrorIs(t, sm.ScheduleRestart(time.Second), ErrNoServiceManager)
	assert.ErrorIs(t, sm.ArmGuard("u", time.Second, "true"), ErrNoServiceManager)
}

func TestPackageRollbackCommand(t *testing.T) {
	for pm, want := range map[string][]string{
		utils.PkgApt:    {"apt-get", "install", "-y", "--allow-downgrades", "alpamon=2.4.0"},
		utils.PkgYum:    {"yum", "downgrade", "-y", "alpamon-2.4.0"},
		utils.PkgZypper: {"zypper", "--non-interactive", "install", "--oldpackage", "alpamon=2.4.0"},
	} {
		got, err := PackageRollbackCommand(pm, "2.4.0")
		require.NoError(t, err)
		assert.Equal(t, want, got)
	}
	_, err := PackageRollbackCommand(utils.PkgApt, "")
	assert.Error(t, err)
	_, err = PackageRollbackCommand(utils.PkgBrew, "2.4.0")
	assert.Error(t, err)
}

func TestShellQuote(t *testing.T) {
	assert.Equal(t, `'a b'`, shellQuote("a b"))
	assert.Equal(t, `'it'\''s'`, shellQuote("it's"))
}

// TestGuardScript runs the generated guard under a real shell, with a fake
// systemctl on PATH, to show it restores only while the marker is present.
func TestGuardScript(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the guard is a POSIX shell script")
	}
	sh, err := exec.LookPath("sh")
	require.NoError(t, err)

	setup := func(t *testing.T) (p *PendingUpgrade, bin, log string, env []string) {
		useTempMarkerDir(t)
		dir := t.TempDir()
		p = binaryMarker(dir)
		require.NoError(t, os.WriteFile(p.BinaryPath, []byte("new"), 0755))
		require.NoError(t, os.WriteFile(p.RollbackPath, []byte("old"), 0755))
		bin = filepath.Join(dir, "bin")
		require.NoError(t, os.Mkdir(bin, 0755))
		log = filepath.Join(dir, "systemctl.log")
		require.NoError(t, os.WriteFile(filepath.Join(bin, "systemctl"), []byte("#!/bin/sh\necho \"$@\" >> "+shellQuote(log)+"\n"), 0755))
		env = append(os.Environ(), "PATH="+bin+":"+os.Getenv("PATH"))
		return p, bin, log, env
	}

	t.Run("marker present restores and restarts", func(t *testing.T) {
		p, _, log, env := setup(t)
		p.GuardUnit = "alpamon-upgrade-guard-7"
		require.NoError(t, WritePending(p))
		script, err := guardScript(p)
		require.NoError(t, err)

		cmd := exec.Command(sh, "-c", script)
		cmd.Env = env
		out, err := cmd.CombinedOutput()
		require.NoError(t, err, string(out))

		got, err := os.ReadFile(p.BinaryPath)
		require.NoError(t, err)
		assert.Equal(t, "old", string(got))
		calls, err := os.ReadFile(log)
		require.NoError(t, err)
		assert.Equal(t, "restart alpamon\n", string(calls))
		_, err = os.Stat(MarkerPath())
		assert.NoError(t, err, "the guard leaves the marker for the restored process to report")
	})

	t.Run("marker armed for another guard is a no-op", func(t *testing.T) {
		p, _, log, env := setup(t)
		p.GuardUnit = "alpamon-upgrade-guard-8"
		require.NoError(t, WritePending(p))
		p.GuardUnit = "alpamon-upgrade-guard-7" // a stale guard from an earlier arming
		script, err := guardScript(p)
		require.NoError(t, err)

		cmd := exec.Command(sh, "-c", script)
		cmd.Env = env
		out, err := cmd.CombinedOutput()
		require.NoError(t, err, string(out))
		assert.Equal(t, "new", fileContent(t, p.BinaryPath))
		_, err = os.Stat(log)
		assert.ErrorIs(t, err, os.ErrNotExist)
	})

	t.Run("marker cleared is a no-op", func(t *testing.T) {
		p, _, log, env := setup(t)
		script, err := guardScript(p)
		require.NoError(t, err)

		cmd := exec.Command(sh, "-c", script)
		cmd.Env = env
		out, err := cmd.CombinedOutput()
		require.NoError(t, err, string(out))

		got, err := os.ReadFile(p.BinaryPath)
		require.NoError(t, err)
		assert.Equal(t, "new", string(got))
		_, err = os.Stat(log)
		assert.ErrorIs(t, err, os.ErrNotExist, "nothing restarted")
	})

	t.Run("package guard reinstalls the previous version", func(t *testing.T) {
		useTempMarkerDir(t)
		script, err := guardScript(&PendingUpgrade{Method: MethodPackage, PackageManager: utils.PkgApt, PreviousPackageVersion: "2.4.0", GuardUnit: "g1"})
		require.NoError(t, err)
		m := shellQuote(MarkerPath())
		assert.Equal(t, "if [ -f "+m+" ] && grep -qF '\"g1\"' "+m+"; then 'apt-get' 'install' '-y' '--allow-downgrades' 'alpamon=2.4.0' && systemctl restart alpamon; fi", script)
	})
}
