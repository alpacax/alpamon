//go:build windows

package executor

import (
	"context"
	"os/exec"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func TestCommandCleanup_CancelTerminatesViaJobAssignment(t *testing.T) {
	cmd := exec.Command("ping", "-n", "60", "127.0.0.1")
	cleanup, err := configureProcessTreeCleanup(cmd, false)
	if err != nil {
		t.Fatalf("configureProcessTreeCleanup: %v", err)
	}
	defer cleanup.close()

	if err := cmd.Start(); err != nil {
		t.Fatalf("cmd.Start: %v", err)
	}
	pid := uint32(cmd.Process.Pid)

	if err := cleanup.afterStart(cmd); err != nil {
		t.Fatalf("afterStart: %v", err)
	}
	if !cleanup.assigned {
		t.Fatal("expected the process to be assigned to the job object")
	}

	if err := cleanup.cancel(cmd); err != nil {
		t.Fatalf("cancel: %v", err)
	}
	waitForCmd(t, cmd)
	waitForWindowsPidGone(t, pid, "process")
}

func TestCommandCleanup_CancelFallsBackToPIDTreeWithoutJobAssignment(t *testing.T) {
	cmd := exec.Command("ping", "-n", "60", "127.0.0.1")
	cleanup, err := configureProcessTreeCleanup(cmd, false)
	if err != nil {
		t.Fatalf("configureProcessTreeCleanup: %v", err)
	}
	defer cleanup.close()

	if err := cmd.Start(); err != nil {
		t.Fatalf("cmd.Start: %v", err)
	}
	pid := uint32(cmd.Process.Pid)

	// Skip afterStart so cancel has no job/handle and must fall back to the PID tree walk alone.
	if err := cleanup.cancel(cmd); err != nil {
		t.Fatalf("cancel: %v", err)
	}
	waitForCmd(t, cmd)
	waitForWindowsPidGone(t, pid, "process")
}

// The assigned job must take a descendant with it: cmd.exe -> ping, both die on cancel.
// (cancel also runs the PID-walk fallback, so this asserts the end state, not job isolation.)
func TestCommandCleanup_CancelTerminatesMultiLevelTreeViaJob(t *testing.T) {
	cmd := exec.Command("cmd", "/c", "ping", "-n", "60", "127.0.0.1")
	cleanup, err := configureProcessTreeCleanup(cmd, false)
	if err != nil {
		t.Fatalf("configureProcessTreeCleanup: %v", err)
	}
	defer cleanup.close()

	if err := cmd.Start(); err != nil {
		t.Fatalf("cmd.Start: %v", err)
	}
	rootPID := uint32(cmd.Process.Pid)

	if err := cleanup.afterStart(cmd); err != nil {
		t.Fatalf("afterStart: %v", err)
	}
	if !cleanup.assigned {
		t.Fatal("expected the process to be assigned to the job object")
	}
	childPID := waitForWindowsChild(t, rootPID)

	if err := cleanup.cancel(cmd); err != nil {
		t.Fatalf("cancel: %v", err)
	}
	waitForCmd(t, cmd)

	waitForWindowsPidGone(t, rootPID, "root process")
	waitForWindowsPidGone(t, childPID, "child process")
}

// cancel racing ahead of afterStart: afterStart must notice canceled==true and re-run cancel.
func TestCommandCleanup_AfterStartReCancelsWhenAlreadyCanceled(t *testing.T) {
	cmd := exec.Command("ping", "-n", "60", "127.0.0.1")
	cleanup, err := configureProcessTreeCleanup(cmd, false)
	if err != nil {
		t.Fatalf("configureProcessTreeCleanup: %v", err)
	}
	defer cleanup.close()

	if err := cmd.Start(); err != nil {
		t.Fatalf("cmd.Start: %v", err)
	}
	pid := uint32(cmd.Process.Pid)

	// cancel runs before afterStart records the pid/handle; afterStart's re-cancel must still leave nothing alive.
	if err := cleanup.cancel(cmd); err != nil {
		t.Fatalf("first cancel: %v", err)
	}
	if !cleanup.canceled {
		t.Fatal("expected canceled to be set after cancel")
	}
	if err := cleanup.afterStart(cmd); err != nil {
		t.Fatalf("afterStart: %v", err)
	}
	waitForCmd(t, cmd)
	waitForWindowsPidGone(t, pid, "process")
}

// Black-box counterpart to the Unix test: cmd.exe runs ping, which inherits and holds stdout open.
// Execute must still return exit 124 promptly instead of blocking on WaitDelay forever.
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
			type result struct {
				exitCode int
				output   string
				err      error
			}
			done := make(chan result, 1)
			go func() {
				exitCode, output, err := NewExecutor().Execute(context.Background(), CommandOptions{
					Args:    []string{"cmd", "/c", "ping", "-n", "60", "127.0.0.1"},
					Timeout: 500 * time.Millisecond,
					PIDHook: tc.pidHook,
				})
				done <- result{exitCode: exitCode, output: output, err: err}
			}()

			var res result
			select {
			case res = <-done:
			case <-time.After(10 * time.Second):
				t.Fatal("executor did not return after timeout; likely blocked on an inherited pipe")
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
		})
	}
}

func waitForCmd(t *testing.T, cmd *exec.Cmd) {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("cmd.Wait did not return after cancel")
	}
}

func isWindowsPidAlive(pid uint32) bool {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.SYNCHRONIZE, false, pid)
	if err != nil {
		return false
	}
	defer windows.CloseHandle(h)
	event, err := windows.WaitForSingleObject(h, 0)
	return err == nil && event == uint32(windows.WAIT_TIMEOUT)
}

// waitForWindowsPidGone fails only if pid is still alive after a bounded wait.
// cancel() tears the tree down through kill-on-job-close, TerminateProcess, and
// a PID-tree walk—all asynchronous on Windows—and waitForCmd only proves the
// root was reaped, not that every job member has finished terminating. Polling
// for the pid to disappear mirrors waitForWindowsChild's poll for it to appear,
// so the check tolerates that teardown latency instead of racing it.
func waitForWindowsPidGone(t *testing.T, pid uint32, what string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if !isWindowsPidAlive(pid) {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("%s %d still running after cancel", what, pid)
}

func waitForWindowsChild(t *testing.T, parent uint32) uint32 {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		children, err := snapshotWindowsChildProcesses()
		if err != nil {
			t.Fatalf("snapshotWindowsChildProcesses: %v", err)
		}
		if kids := children[parent]; len(kids) > 0 {
			return kids[0]
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("child of process %d did not appear", parent)
	return 0
}
