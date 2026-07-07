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
)

func TestConfigureProcessTreeCleanup_FlagMatrix(t *testing.T) {
	t.Run("non_session_leader_sets_pgid", func(t *testing.T) {
		cmd := &exec.Cmd{}
		if _, err := configureProcessTreeCleanup(cmd, false); err != nil {
			t.Fatalf("configureProcessTreeCleanup: %v", err)
		}
		if cmd.SysProcAttr == nil {
			t.Fatal("SysProcAttr was not allocated")
		}
		if !cmd.SysProcAttr.Setpgid {
			t.Error("Setpgid: got false, want true")
		}
		if cmd.SysProcAttr.Setsid {
			t.Error("Setsid: got true, want false")
		}
	})

	t.Run("session_leader_sets_sid_not_pgid", func(t *testing.T) {
		cmd := &exec.Cmd{}
		if _, err := configureProcessTreeCleanup(cmd, true); err != nil {
			t.Fatalf("configureProcessTreeCleanup: %v", err)
		}
		if !cmd.SysProcAttr.Setsid {
			t.Error("Setsid: got false, want true")
		}
		if cmd.SysProcAttr.Setpgid {
			t.Error("Setpgid: got true, want false (setpgid on a setsid session leader is EPERM, fails Start)")
		}
	})

	// A caller that already asked for setsid must not also get Setpgid forced on.
	t.Run("preexisting_setsid_not_overridden", func(t *testing.T) {
		cmd := &exec.Cmd{SysProcAttr: &syscall.SysProcAttr{Setsid: true}}
		if _, err := configureProcessTreeCleanup(cmd, false); err != nil {
			t.Fatalf("configureProcessTreeCleanup: %v", err)
		}
		if cmd.SysProcAttr.Setpgid {
			t.Error("Setpgid was forced on despite preexisting Setsid")
		}
	})

	// The credential from utils.Demote is assigned before this runs; it must survive.
	t.Run("preserves_existing_credential", func(t *testing.T) {
		cred := &syscall.Credential{Uid: 1000, Gid: 1000}
		cmd := &exec.Cmd{SysProcAttr: &syscall.SysProcAttr{Credential: cred}}
		if _, err := configureProcessTreeCleanup(cmd, false); err != nil {
			t.Fatalf("configureProcessTreeCleanup: %v", err)
		}
		if cmd.SysProcAttr.Credential != cred {
			t.Error("Credential was clobbered by configureProcessTreeCleanup")
		}
		if !cmd.SysProcAttr.Setpgid {
			t.Error("Setpgid was not set alongside the preserved credential")
		}
	})
}

func TestCommandCleanup_CancelNilProcessReturnsProcessDone(t *testing.T) {
	var cleanup commandCleanup
	if err := cleanup.cancel(&exec.Cmd{}); !errors.Is(err, os.ErrProcessDone) {
		t.Fatalf("cancel: got %v, want os.ErrProcessDone", err)
	}
}

// White-box counterpart to the Windows job-object test: configure -> Start -> cancel must SIGKILL
// the whole group, so a backgrounded grandchild holding the pipe open dies too.
func TestCommandCleanup_CancelKillsProcessGroup(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "child.pid")
	cmd := exec.Command("/bin/sh", "-c", "sleep 600 & echo $! > \"$1\"; wait", "sh", pidFile)
	cleanup, err := configureProcessTreeCleanup(cmd, false)
	if err != nil {
		t.Fatalf("configureProcessTreeCleanup: %v", err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("cmd.Start: %v", err)
	}
	if err := cleanup.afterStart(cmd); err != nil {
		t.Fatalf("afterStart: %v", err)
	}

	childPID := readExecutorTimeoutChildPID(t, pidFile)
	t.Cleanup(func() { _ = syscall.Kill(childPID, syscall.SIGKILL) })

	if err := cleanup.cancel(cmd); err != nil {
		t.Fatalf("cancel: %v", err)
	}
	go func() { _ = cmd.Wait() }()

	if !waitForExecutorTimeoutChildExit(childPID, 3*time.Second) {
		t.Fatalf("grandchild %d survived the group kill", childPID)
	}
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
			script := "sleep 600 & echo $! > \"$1\"; wait"

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
				pid := readExecutorTimeoutChildPID(t, pidFile)
				_ = syscall.Kill(pid, syscall.SIGKILL)
				t.Fatalf("executor did not return after timeout; leaked child pid %d", pid)
			}

			if res.exitCode != 124 {
				t.Fatalf("exit code: got %d, want 124; err=%v output=%q", res.exitCode, res.err, res.output)
			}
			if res.err == nil {
				t.Fatal("expected timeout error")
			}
			if !strings.Contains(res.output, "Command timed out after") {
				t.Fatalf("expected timeout banner, got %q", res.output)
			}

			pid := readExecutorTimeoutChildPID(t, pidFile)
			t.Cleanup(func() {
				_ = syscall.Kill(pid, syscall.SIGKILL)
			})
			if !waitForExecutorTimeoutChildExit(pid, 3*time.Second) {
				t.Fatalf("child process %d was still alive after executor timeout cleanup", pid)
			}
		})
	}
}

// A non-zero exit while a backgrounded descendant holds the inherited pipe must still reap it: no
// timeout means no Cancel, and Wait returns ExitError not ErrWaitDelay, so only the unconditional cancel covers it.
func TestExecutor_CleansDescendantWhenCommandExitsNonZero(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "child.pid")
	script := "sleep 600 & echo $! > \"$1\"; exit 3"

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
		pid := readExecutorTimeoutChildPID(t, pidFile)
		_ = syscall.Kill(pid, syscall.SIGKILL)
		t.Fatalf("executor did not return; leaked child pid %d", pid)
	}

	if res.exitCode != 3 {
		t.Fatalf("exit code: got %d, want 3; err=%v", res.exitCode, res.err)
	}

	pid := readExecutorTimeoutChildPID(t, pidFile)
	t.Cleanup(func() { _ = syscall.Kill(pid, syscall.SIGKILL) })
	if !waitForExecutorTimeoutChildExit(pid, 3*time.Second) {
		t.Fatalf("descendant %d survived after a non-zero command exit", pid)
	}
}

func readExecutorTimeoutChildPID(t *testing.T, path string) int {
	t.Helper()

	deadline := time.Now().Add(2 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		data, err := os.ReadFile(path)
		if err == nil {
			pid, convErr := strconv.Atoi(strings.TrimSpace(string(data)))
			if convErr != nil {
				t.Fatalf("invalid pid file %q: %v", string(data), convErr)
			}
			return pid
		}
		lastErr = err
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("pid file was not written: %s: %v", path, lastErr)
	return 0
}

func waitForExecutorTimeoutChildExit(pid int, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if processGone(pid) {
			return true
		}
		time.Sleep(20 * time.Millisecond)
	}
	return processGone(pid)
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
