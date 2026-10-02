//go:build !windows

package executor

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConfigureProcessTreeCleanup_FlagMatrix(t *testing.T) {
	t.Run("non_session_leader_sets_pgid", func(t *testing.T) {
		cmd := &exec.Cmd{}
		cleanup, err := configureProcessTreeCleanup(cmd, false)
		require.NoError(t, err, "configureProcessTreeCleanup")
		require.NotNil(t, cmd.SysProcAttr, "SysProcAttr was not allocated")
		assert.True(t, cmd.SysProcAttr.Setpgid, "Setpgid: got false, want true")
		assert.False(t, cmd.SysProcAttr.Setsid, "Setsid: got true, want false")
		assert.True(t, cleanup.leadsGroup, "leadsGroup: got false, want true for setpgid(0,0)")
	})

	t.Run("session_leader_sets_sid_not_pgid", func(t *testing.T) {
		cmd := &exec.Cmd{}
		cleanup, err := configureProcessTreeCleanup(cmd, true)
		require.NoError(t, err, "configureProcessTreeCleanup")
		assert.True(t, cmd.SysProcAttr.Setsid, "Setsid: got false, want true")
		assert.False(t, cmd.SysProcAttr.Setpgid, "Setpgid: got true, want false (setpgid on a setsid session leader is EPERM, fails Start)")
		assert.True(t, cleanup.leadsGroup, "leadsGroup: got false, want true for setsid")
	})

	// A caller that already asked for setsid must not also get Setpgid forced on.
	t.Run("preexisting_setsid_not_overridden", func(t *testing.T) {
		cmd := &exec.Cmd{SysProcAttr: &syscall.SysProcAttr{Setsid: true}}
		cleanup, err := configureProcessTreeCleanup(cmd, false)
		require.NoError(t, err, "configureProcessTreeCleanup")
		assert.False(t, cmd.SysProcAttr.Setpgid, "Setpgid was forced on despite preexisting Setsid")
		assert.True(t, cleanup.leadsGroup, "leadsGroup: got false, want true for preexisting setsid")
	})

	// Joining an existing group means PGID != PID, so afterStart must fall back to the getpgid guard.
	t.Run("preexisting_pgid_is_not_own_group_leader", func(t *testing.T) {
		cmd := &exec.Cmd{SysProcAttr: &syscall.SysProcAttr{Setpgid: true, Pgid: 1234}}
		cleanup, err := configureProcessTreeCleanup(cmd, false)
		require.NoError(t, err, "configureProcessTreeCleanup")
		assert.False(t, cleanup.leadsGroup, "leadsGroup: got true, want false for a child joining an existing group")
	})

	// The credential from utils.Demote is assigned before this runs; it must survive.
	t.Run("preserves_existing_credential", func(t *testing.T) {
		cred := &syscall.Credential{Uid: 1000, Gid: 1000}
		cmd := &exec.Cmd{SysProcAttr: &syscall.SysProcAttr{Credential: cred}}
		cleanup, err := configureProcessTreeCleanup(cmd, false)
		require.NoError(t, err, "configureProcessTreeCleanup")
		assert.Same(t, cred, cmd.SysProcAttr.Credential, "Credential was clobbered by configureProcessTreeCleanup")
		assert.True(t, cmd.SysProcAttr.Setpgid, "Setpgid was not set alongside the preserved credential")
		assert.True(t, cleanup.leadsGroup, "leadsGroup: got false, want true alongside the preserved credential")
	})
}

// When a cancel races ahead of the process group being recorded, afterStart redoes the kill. runCommand
// always runs afterStart before Wait, so the redo targets a still-unreaped process—never a reaped pid the
// OS could have handed to an unrelated process. Exercise that exact order and assert the redo reached the
// whole group: a backgrounded grandchild that survived the raced cancel must die. Reap only after.
func TestCommandCleanup_AfterStartRedoAfterRacedCancel(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "child.pid")
	cmd := exec.Command("/bin/sh", "-c", bgChildScript("wait"), "sh", pidFile)
	cleanup, err := configureProcessTreeCleanup(cmd, false)
	require.NoError(t, err, "configureProcessTreeCleanup")
	err = cmd.Start()
	require.NoError(t, err, "cmd.Start")
	// Reap last—after afterStart, and even when an assertion below fails early.
	t.Cleanup(func() { _ = cmd.Wait() })

	childPID := readChildPID(t, pidFile)
	t.Cleanup(func() { _ = syscall.Kill(childPID, syscall.SIGKILL) })

	// Cancel before the group is recorded: pgid is still 0, so only the leader is targeted.
	err = cleanup.cancel(cmd)
	if err != nil {
		require.ErrorIs(t, err, os.ErrProcessDone, "cancel")
	}
	// Let the SIGKILL land before the redo: an unreaped-zombie leader is the state that used to defeat
	// getpgid, and the redo must cope with it. The raced cancel reaches only the leader, so the grandchild
	// must still be alive—otherwise the assertion below cannot tell a working redo from a no-op one.
	require.True(t, waitForLeaderStopped(cmd.Process.Pid, 3*time.Second), "leader %d still running after the raced cancel", cmd.Process.Pid)
	require.False(t, processGone(childPID), "grandchild %d died with the raced cancel; the redo is not exercised", childPID)

	// Redo while the process is still unreaped, matching runCommand's afterStart-before-Wait order.
	err = cleanup.afterStart(cmd)
	require.NoError(t, err, "afterStart redo surfaced an error, want nil after a raced cancel")
	require.True(t, waitForProcessGone(childPID, 3*time.Second), "grandchild %d survived the afterStart redo", childPID)
}

// afterStart swallows os.ErrProcessDone from its redo so Wait reports the real termination status instead
// of exit 1 with "os: process already finished". runCommand can't reach it—afterStart always precedes
// Wait, so the group still holds the unreaped leader—so pin the branch white-box on a reaped cmd.
func TestCommandCleanup_AfterStartRedoSwallowsProcessDone(t *testing.T) {
	cmd := exec.Command("/bin/sh", "-c", "exit 0")
	cleanup, err := configureProcessTreeCleanup(cmd, false)
	require.NoError(t, err, "configureProcessTreeCleanup")
	err = cmd.Start()
	require.NoError(t, err, "cmd.Start")
	pid := cmd.Process.Pid
	err = cmd.Wait()
	require.NoError(t, err, "cmd.Wait")
	// Reaped, so the group must be empty; skip rather than signal a group the OS already handed out.
	if !errors.Is(syscall.Kill(-pid, 0), syscall.ESRCH) {
		t.Skipf("pgid %d was reused, cannot exercise an already-gone group", pid)
	}

	cleanup.takeForCancel() // a cancel raced ahead, so afterStart redoes the kill
	err = cleanup.afterStart(cmd)
	require.NoError(t, err, "afterStart: want nil for an already-gone group")
}

func TestCommandCleanup_CancelNilProcessReturnsProcessDone(t *testing.T) {
	var cleanup commandCleanup
	err := cleanup.cancel(&exec.Cmd{})
	require.ErrorIs(t, err, os.ErrProcessDone, "cancel")
}

// White-box counterpart to the Windows job-object test: configure -> Start -> cancel must SIGKILL
// the whole group, so a backgrounded grandchild holding the pipe open dies too.
func TestCommandCleanup_CancelKillsProcessGroup(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "child.pid")
	cmd := exec.Command("/bin/sh", "-c", bgChildScript("wait"), "sh", pidFile)
	cleanup, err := configureProcessTreeCleanup(cmd, false)
	require.NoError(t, err, "configureProcessTreeCleanup")
	err = cmd.Start()
	require.NoError(t, err, "cmd.Start")
	// Kill and reap the leader even when an assertion below fails before cancel runs; the in-body
	// cancel makes this a no-op on the happy path.
	t.Cleanup(func() {
		_ = cleanup.cancel(cmd)
		_ = cmd.Wait()
	})
	err = cleanup.afterStart(cmd)
	require.NoError(t, err, "afterStart")

	childPID := readChildPID(t, pidFile)
	t.Cleanup(func() { _ = syscall.Kill(childPID, syscall.SIGKILL) })

	err = cleanup.cancel(cmd)
	require.NoError(t, err, "cancel")

	require.True(t, waitForProcessGone(childPID, 3*time.Second), "grandchild %d survived the group kill", childPID)
}

// Black-box counterpart: a timed-out command whose backgrounded grandchild holds stdout open
// must still return exit 124 promptly, and the grandchild must be killed with the group.
func TestExecutor_TimeoutCleansProcessTreeWhenChildKeepsPipeOpen(t *testing.T) {
	for _, tc := range []struct {
		name    string
		pidHook func(pid int)
	}{
		{
			name: "plain",
		},
		{
			name:    "pid_hook",
			pidHook: func(pid int) {},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pidFile := filepath.Join(t.TempDir(), "child.pid")
			script := bgChildScript("wait")

			type result struct {
				exitCode int
				output   string
				err      error
			}
			done := make(chan result, 1)
			go func() {
				exitCode, output, err := NewExecutor().Execute(context.Background(), CommandOptions{
					Args:    []string{"/bin/sh", "-c", script, "sh", pidFile},
					Timeout: 200 * time.Millisecond,
					PIDHook: tc.pidHook,
				})
				done <- result{exitCode: exitCode, output: output, err: err}
			}()

			var res result
			select {
			case res = <-done:
			case <-time.After(5 * time.Second):
				pid := readChildPID(t, pidFile)
				_ = syscall.Kill(pid, syscall.SIGKILL)
				t.Fatalf("executor did not return after timeout; leaked child pid %d", pid)
			}

			require.Equal(t, 124, res.exitCode, "err=%v output=%q", res.err, res.output)
			require.Error(t, res.err, "expected timeout error")
			require.Contains(t, res.output, "Command timed out after", "expected timeout banner")

			pid := readChildPID(t, pidFile)
			t.Cleanup(func() {
				_ = syscall.Kill(pid, syscall.SIGKILL)
			})
			require.True(t, waitForProcessGone(pid, 3*time.Second), "child process %d was still alive after executor timeout cleanup", pid)
		})
	}
}

// A non-zero exit while a backgrounded descendant holds the inherited pipe must still reap it: no
// timeout means no Cancel, and Wait returns ExitError not ErrWaitDelay, so only the unconditional cancel covers it.
func TestExecutor_CleansDescendantWhenCommandExitsNonZero(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "child.pid")
	script := bgChildScript("exit 3")

	type result struct {
		exitCode int
		err      error
	}
	done := make(chan result, 1)
	go func() {
		exitCode, _, err := NewExecutor().Execute(context.Background(), CommandOptions{
			Args: []string{"/bin/sh", "-c", script, "sh", pidFile},
		})
		done <- result{exitCode: exitCode, err: err}
	}()

	var res result
	select {
	case res = <-done:
	case <-time.After(10 * time.Second):
		pid := readChildPID(t, pidFile)
		_ = syscall.Kill(pid, syscall.SIGKILL)
		t.Fatalf("executor did not return; leaked child pid %d", pid)
	}

	require.Equal(t, 3, res.exitCode, "err=%v", res.err)

	pid := readChildPID(t, pidFile)
	t.Cleanup(func() { _ = syscall.Kill(pid, syscall.SIGKILL) })
	require.True(t, waitForProcessGone(pid, 3*time.Second), "descendant %d survived after a non-zero command exit", pid)
}

// bgChildScript backgrounds a long sleeper and publishes its pid atomically: echo truncate-opens the
// target, so write to a temp file and rename it in (a same-directory rename(2) is atomic).
func bgChildScript(tail string) string {
	return `sleep 600 & echo $! > "$1.tmp"; mv "$1.tmp" "$1"; ` + tail
}

func readChildPID(t *testing.T, path string) int {
	t.Helper()

	deadline := time.Now().Add(2 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		data, err := os.ReadFile(path)
		if err == nil {
			pid, convErr := strconv.Atoi(strings.TrimSpace(string(data)))
			require.NoError(t, convErr, "invalid pid file %q", string(data))
			return pid
		}
		lastErr = err
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("pid file was not written: %s: %v", path, lastErr)
	return 0
}

func waitForProcessGone(pid int, timeout time.Duration) bool {
	return waitFor(timeout, func() bool { return processGone(pid) })
}

// waitForLeaderStopped waits until the SIGKILL landed but Wait has not reaped the leader yet. Detection is
// split because the platforms disagree about zombies: on linux processGone reads the Z state from /proc,
// while on darwin getpgid is what stops seeing the leader (proc_find skips SZOMB).
func waitForLeaderStopped(pid int, timeout time.Duration) bool {
	return waitFor(timeout, func() bool {
		if processGone(pid) {
			return true
		}
		_, err := syscall.Getpgid(pid)
		return errors.Is(err, syscall.ESRCH)
	})
}

// waitFor polls cond every 20ms until it reports true or timeout elapses.
func waitFor(timeout time.Duration, cond func() bool) bool {
	deadline := time.Now().Add(timeout)
	for {
		if cond() {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// processGone also accepts a zombie as gone: kill(pid, 0) still succeeds for one, and in a CI container with no init process to reap the orphaned grandchild it stays a zombie indefinitely.
func processGone(pid int) bool {
	if errors.Is(syscall.Kill(pid, 0), syscall.ESRCH) {
		return true
	}
	if runtime.GOOS != "linux" {
		return false
	}
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return true
	}
	idx := strings.LastIndexByte(string(data), ')')
	return idx != -1 && idx+2 < len(data) && data[idx+2] == 'Z'
}
