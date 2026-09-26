package updater

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
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

	want := binaryMarker(t, t.TempDir())
	want.GuardUnit = "alpamon-upgrade-guard-3"
	want.StartedAt, want.Deadline = time.Unix(100, 0).UTC(), time.Unix(400, 0).UTC()
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

// binaryMarker is a valid binary-method marker for a stand-in binary in dir,
// which it makes the running binary for marker validation.
func binaryMarker(t *testing.T, dir string) *PendingUpgrade {
	t.Helper()
	useBinaryPath(t, filepath.Join(dir, "alpamon"))
	now := time.Now()
	return &PendingUpgrade{
		StartedAt: now.UTC(), Deadline: now.UTC().Add(time.Minute),
		AttemptID: "att", FromVersion: "2.4.0", ToVersion: "2.5.0", Method: MethodBinary,
		BinaryPath: filepath.Join(dir, "alpamon"), RollbackPath: filepath.Join(dir, "alpamon.rollback"),
	}
}

func TestBeginTransition_WritesMarkerThenArmsGuard(t *testing.T) {
	useTempMarkerDir(t)
	sm := &fakeServiceManager{}
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	p := binaryMarker(t, t.TempDir())

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
	require.NotNil(t, sm.markersAtArm[0], "the marker is on disk when the guard is armed")
	assert.Equal(t, guards[0].unit, sm.markersAtArm[0].GuardUnit)
	assert.Equal(t, RestartDelay+3*time.Minute+guardMargin, guards[0].delay, "the guard fires after the deadline")
	assert.Contains(t, guards[0].script, shellQuote(MarkerPath()))
}

func TestBeginTransition_RefusesWhileAnotherIsPending(t *testing.T) {
	useTempMarkerDir(t)
	dir := t.TempDir()
	earlier := binaryMarker(t, dir)
	earlier.AttemptID, earlier.Deadline = "earlier", time.Now().Add(time.Minute)
	require.NoError(t, WritePending(earlier))
	sm := &fakeServiceManager{}

	_, err := BeginTransition(binaryMarker(t, dir), sm, 0, time.Minute, time.Now())
	assert.ErrorIs(t, err, ErrUpgradePending)
	_, guards, _ := sm.snapshot()
	assert.Empty(t, guards)
	stored, _ := LoadPending()
	assert.Equal(t, "earlier", stored.AttemptID, "the pending marker is left alone")
}

func TestBeginTransition_DiscardsAStaleMarker(t *testing.T) {
	useTempMarkerDir(t)
	now := time.Now()
	dir := t.TempDir()
	abandoned := binaryMarker(t, dir)
	abandoned.AttemptID, abandoned.GuardUnit, abandoned.Deadline = "abandoned", "alpamon-upgrade-guard-5", now.Add(-staleMarkerAge-time.Minute)
	abandoned.StartedAt = abandoned.Deadline.Add(-time.Minute)
	require.NoError(t, WritePending(abandoned))
	sm := &fakeServiceManager{}

	_, err := BeginTransition(binaryMarker(t, dir), sm, 0, time.Minute, now)
	require.NoError(t, err)
	stored, err := LoadPending()
	require.NoError(t, err)
	assert.Equal(t, "att", stored.AttemptID)
	_, _, disarmed := sm.snapshot()
	assert.Equal(t, []string{"alpamon-upgrade-guard-5"}, disarmed)
}

func TestBeginTransition_SettleDelaysDeadlineAndGuard(t *testing.T) {
	useTempMarkerDir(t)
	sm := &fakeServiceManager{}
	now := time.Now()
	p := binaryMarker(t, t.TempDir())

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

func TestRearm_FailureKeepsTheFirstGuardInCharge(t *testing.T) {
	useTempMarkerDir(t)
	sm := &fakeServiceManager{}
	p := binaryMarker(t, t.TempDir())
	now := time.Now()
	_, err := BeginTransition(p, sm, 30*time.Minute, time.Minute, now)
	require.NoError(t, err)
	first, firstDeadline := p.GuardUnit, p.Deadline

	sm.guardErr = errors.New("systemd-run: boom")
	require.Error(t, Rearm(p, sm, time.Minute, now.Add(time.Minute)))

	stored, err := LoadPending()
	require.NoError(t, err)
	require.NotNil(t, stored, "the marker survives")
	assert.Equal(t, first, stored.GuardUnit, "and still names the guard that is armed")
	assert.Equal(t, firstDeadline, stored.Deadline)
	assert.Equal(t, first, p.GuardUnit)
	_, _, disarmed := sm.snapshot()
	assert.Empty(t, disarmed)
}

func TestBeginTransition_WithoutServiceManager(t *testing.T) {
	useTempMarkerDir(t)
	_, err := BeginTransition(binaryMarker(t, t.TempDir()), noServiceManager{}, 0, time.Minute, time.Now())
	require.NoError(t, err)
	stored, err := LoadPending()
	require.NoError(t, err)
	assert.Empty(t, stored.GuardUnit, "no guard is recorded when none could be armed")
}

func TestBeginTransition_GuardFailureAborts(t *testing.T) {
	useTempMarkerDir(t)
	sm := &fakeServiceManager{guardErr: errors.New("systemd-run: boom")}

	_, err := BeginTransition(binaryMarker(t, t.TempDir()), sm, 0, time.Minute, time.Now())
	assert.ErrorContains(t, err, "arm upgrade guard")
	stored, err := LoadPending()
	require.NoError(t, err)
	assert.Nil(t, stored, "a failed guard leaves no marker behind")
}

func TestBeginTransition_AbortUndoesEverything(t *testing.T) {
	useTempMarkerDir(t)
	dir := t.TempDir()
	p := binaryMarker(t, dir)
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
		m := &systemdManager{run: r.run, sleep: func(time.Duration) {}}
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
		m := &systemdManager{run: r.run, sleep: func(time.Duration) {}}
		assert.Error(t, m.ScheduleRestart(time.Second), "both attempts fail with the fake error")
		calls := r.snapshot()
		require.Len(t, calls, 2)
		assert.Equal(t, "--collect", calls[0][1])
		assert.NotContains(t, calls[1], "--collect")
	})

	t.Run("disarm stops the timer", func(t *testing.T) {
		r := &fakeRunner{}
		m := &systemdManager{run: r.run, sleep: func(time.Duration) {}}
		m.DisarmGuard("")
		assert.Empty(t, r.snapshot(), "no unit, nothing to stop")
		r.err = errors.New("inactive") // is-active exits non-zero
		assert.False(t, m.DisarmGuard("g1"))
		assert.Equal(t, []string{"systemctl", "stop", "g1.timer"}, r.snapshot()[0], "only the timer is stopped")
	})

	t.Run("disarm waits for a guard that is already running", func(t *testing.T) {
		polls := 0
		var calls [][]string
		m := &systemdManager{
			run: func(_ context.Context, name string, args ...string) ([]byte, error) {
				calls = append(calls, append([]string{name}, args...))
				if len(args) > 0 && args[0] == "is-active" {
					polls++
					if polls <= 3 {
						return []byte("active\n"), nil
					}
					return []byte("inactive\n"), errors.New("exit status 3")
				}
				return nil, nil
			},
			sleep: func(time.Duration) {},
		}
		assert.True(t, m.DisarmGuard("g1"), "a guard that ran reports as fired")
		assert.Equal(t, 4, polls)
		for _, c := range calls {
			assert.NotEqual(t, []string{"systemctl", "stop", "g1.service"}, c, "a running guard is never stopped")
		}
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
		got, err := PackageRollbackCommand(pm, "2.4.0", "2.5.0")
		require.NoError(t, err)
		assert.Equal(t, want, got)
	}
	_, err := PackageRollbackCommand(utils.PkgApt, "", "2.5.0")
	assert.Error(t, err)
	_, err = PackageRollbackCommand(utils.PkgApt, "-oAPT::x", "2.5.0")
	assert.Error(t, err, "a version that could read as an option is refused")
	_, err = PackageRollbackCommand(utils.PkgBrew, "2.4.0", "2.5.0")
	assert.Error(t, err)

	// After a pinned downgrade the version to go back to is the newer one.
	got, err := PackageRollbackCommand(utils.PkgYum, "2.6.0", "2.5.0")
	require.NoError(t, err)
	assert.Equal(t, []string{"yum", "install", "-y", "alpamon-2.6.0"}, got)
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
		p = binaryMarker(t, dir)
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

	t.Run("unit name in another field does not match", func(t *testing.T) {
		p, _, log, env := setup(t)
		p.GuardUnit = "alpamon-upgrade-guard-8"
		p.AttemptID = `"guard_unit": "alpamon-upgrade-guard-7"`
		require.NoError(t, WritePending(p))
		p.GuardUnit = "alpamon-upgrade-guard-7"
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
		assert.Equal(t, "if [ -f "+m+" ] && grep -qxF '  \"guard_unit\": \"g1\",' "+m+"; then 'apt-get' 'install' '-y' '--allow-downgrades' 'alpamon=2.4.0' && systemctl restart alpamon; fi", script)
	})
}

func TestLoadPending_DiscardsMarkersItDidNotWrite(t *testing.T) {
	valid := func(t *testing.T) *PendingUpgrade {
		p := binaryMarker(t, t.TempDir())
		p.GuardUnit = "alpamon-upgrade-guard-1"
		return p
	}
	tests := []struct {
		name   string
		mutate func(p *PendingUpgrade)
	}{
		{"foreign binary path", func(p *PendingUpgrade) { p.BinaryPath = "/etc/shadow" }},
		{"foreign rollback path", func(p *PendingUpgrade) { p.RollbackPath = "/tmp/evil" }},
		{"foreign guard unit", func(p *PendingUpgrade) { p.GuardUnit = "sshd" }},
		{"no start time", func(p *PendingUpgrade) { p.StartedAt = time.Time{} }},
		{"deadline before start", func(p *PendingUpgrade) { p.Deadline = p.StartedAt.Add(-time.Second) }},
		{"deadline too far out", func(p *PendingUpgrade) { p.Deadline = p.StartedAt.Add(maxMarkerSpan + time.Second) }},
		{"unknown method", func(p *PendingUpgrade) { p.Method = "script" }},
		{"bad target version", func(p *PendingUpgrade) { p.ToVersion = "2.5.0; reboot" }},
		{"bad previous version", func(p *PendingUpgrade) { p.FromVersion = "latest" }},
		{"package fields on a binary marker", func(p *PendingUpgrade) { p.PreviousPackageVersion = "2.4.0" }},
		{"foreign package manager", func(p *PendingUpgrade) {
			p.Method, p.BinaryPath, p.RollbackPath = MethodPackage, "", ""
			p.PackageManager, p.PreviousPackageVersion = "pacman", "2.4.0"
		}},
		{"option-shaped package version", func(p *PendingUpgrade) {
			p.Method, p.BinaryPath, p.RollbackPath = MethodPackage, "", ""
			p.PackageManager, p.PreviousPackageVersion = utils.PackageManager, "--config=/tmp/x"
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			useTempMarkerDir(t)
			p := valid(t)
			tt.mutate(p)
			assert.Error(t, WritePending(p), "the writer refuses it too")

			data, err := json.MarshalIndent(p, "", "  ")
			require.NoError(t, err)
			require.NoError(t, os.WriteFile(MarkerPath(), data, 0600))

			got, err := LoadPending()
			require.NoError(t, err)
			assert.Nil(t, got)
			_, err = os.Stat(MarkerPath())
			assert.ErrorIs(t, err, os.ErrNotExist, "an invalid marker is removed")
		})
	}

	t.Run("trailing data", func(t *testing.T) {
		useTempMarkerDir(t)
		p := valid(t)
		require.NoError(t, WritePending(p))
		data, err := os.ReadFile(MarkerPath())
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(MarkerPath(), append(data, []byte(`{"method":"binary"}`)...), 0600))
		got, err := LoadPending()
		require.NoError(t, err)
		assert.Nil(t, got)
	})

	t.Run("unknown field", func(t *testing.T) {
		useTempMarkerDir(t)
		p := valid(t)
		require.NoError(t, WritePending(p))
		data, err := os.ReadFile(MarkerPath())
		require.NoError(t, err)
		data = []byte(strings.Replace(string(data), "{", `{"script": "x",`, 1))
		require.NoError(t, os.WriteFile(MarkerPath(), data, 0600))
		got, err := LoadPending()
		require.NoError(t, err)
		assert.Nil(t, got)
	})

	if runtime.GOOS != "windows" {
		t.Run("writable by others", func(t *testing.T) {
			useTempMarkerDir(t)
			require.NoError(t, WritePending(valid(t)))
			require.NoError(t, os.Chmod(MarkerPath(), 0o666))
			got, err := LoadPending()
			require.NoError(t, err)
			assert.Nil(t, got)
		})
	}

	t.Run("valid marker loads", func(t *testing.T) {
		useTempMarkerDir(t)
		p := valid(t)
		require.NoError(t, WritePending(p))
		got, err := LoadPending()
		require.NoError(t, err)
		assert.Equal(t, p, got)
		entries, err := os.ReadDir(filepath.Dir(MarkerPath()))
		require.NoError(t, err)
		assert.Len(t, entries, 1, "no temp file is left behind")
	})
}
