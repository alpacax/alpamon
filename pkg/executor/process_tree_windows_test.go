//go:build windows

package executor

import (
	"context"
	"os/exec"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

func TestCommandCleanup_CancelTerminatesViaJobAssignment(t *testing.T) {
	cmd := exec.Command("ping", "-n", "60", "127.0.0.1")
	cleanup, err := configureProcessTreeCleanup(cmd, false)
	require.NoError(t, err, "configureProcessTreeCleanup")
	defer cleanup.close()

	err = cmd.Start()
	require.NoError(t, err, "cmd.Start")
	pid := uint32(cmd.Process.Pid)

	err = cleanup.afterStart(cmd)
	require.NoError(t, err, "afterStart")
	require.True(t, cleanup.assigned, "expected the process to be assigned to the job object")

	err = cleanup.cancel(cmd)
	require.NoError(t, err, "cancel")
	waitForCmd(t, cmd)
	waitForWindowsPidGone(t, pid, "after cancel via job assignment")
}

func TestCommandCleanup_CancelFallsBackToPIDTreeWithoutJobAssignment(t *testing.T) {
	cmd := exec.Command("ping", "-n", "60", "127.0.0.1")
	cleanup, err := configureProcessTreeCleanup(cmd, false)
	require.NoError(t, err, "configureProcessTreeCleanup")
	defer cleanup.close()

	err = cmd.Start()
	require.NoError(t, err, "cmd.Start")
	pid := uint32(cmd.Process.Pid)

	// Skip afterStart so cancel has no job/handle and must fall back to the PID tree walk alone.
	err = cleanup.cancel(cmd)
	require.NoError(t, err, "cancel")
	waitForCmd(t, cmd)
	waitForWindowsPidGone(t, pid, "after cancel via PID-tree fallback")
}

// The assigned job must take a descendant with it: cmd.exe -> ping, both die on cancel.
// (cancel also runs the PID-walk fallback, so this asserts the end state, not job isolation.)
func TestCommandCleanup_CancelTerminatesMultiLevelTreeViaJob(t *testing.T) {
	cmd := exec.Command("cmd", "/c", "ping", "-n", "60", "127.0.0.1")
	cleanup, err := configureProcessTreeCleanup(cmd, false)
	require.NoError(t, err, "configureProcessTreeCleanup")
	defer cleanup.close()

	err = cmd.Start()
	require.NoError(t, err, "cmd.Start")
	rootPID := uint32(cmd.Process.Pid)

	err = cleanup.afterStart(cmd)
	require.NoError(t, err, "afterStart")
	require.True(t, cleanup.assigned, "expected the process to be assigned to the job object")
	childPID := waitForWindowsChild(t, rootPID)

	err = cleanup.cancel(cmd)
	require.NoError(t, err, "cancel")
	waitForCmd(t, cmd)

	waitForWindowsPidGone(t, rootPID, "root process after cancel")
	waitForWindowsPidGone(t, childPID, "child process after cancel")
}

// cancel racing ahead of afterStart: afterStart must notice canceled==true and re-run cancel.
func TestCommandCleanup_AfterStartReCancelsWhenAlreadyCanceled(t *testing.T) {
	cmd := exec.Command("ping", "-n", "60", "127.0.0.1")
	cleanup, err := configureProcessTreeCleanup(cmd, false)
	require.NoError(t, err, "configureProcessTreeCleanup")
	defer cleanup.close()

	err = cmd.Start()
	require.NoError(t, err, "cmd.Start")
	pid := uint32(cmd.Process.Pid)

	// cancel runs before afterStart records the pid/handle; afterStart's re-cancel must still leave nothing alive.
	err = cleanup.cancel(cmd)
	require.NoError(t, err, "first cancel")
	require.True(t, cleanup.canceled, "expected canceled to be set after cancel")
	err = cleanup.afterStart(cmd)
	require.NoError(t, err, "afterStart")
	waitForCmd(t, cmd)
	waitForWindowsPidGone(t, pid, "after afterStart re-cancel")
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

			require.Equal(t, 124, res.exitCode, "err=%v output=%q", res.err, res.output)
			require.Error(t, res.err, "expected timeout error")
			require.Contains(t, res.output, "Command timed out after", "expected timeout banner")
		})
	}
}

// One bound for every wait in this file: the same teardown latency is what all
// of them are tolerating, so widening it is a single edit.
const (
	windowsPollDeadline = 3 * time.Second
	windowsPollInterval = 50 * time.Millisecond
)

func waitForCmd(t *testing.T, cmd *exec.Cmd) {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case <-done:
	case <-time.After(windowsPollDeadline):
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
// cancel() tears the tree down asynchronously (kill-on-job-close,
// TerminateProcess, PID-tree walk), and waitForCmd only proves the root was
// reaped—not that every job member has finished terminating.
//
// Only the child-pid assertion was ever racy (#382); where cmd.Wait already
// reaped the pid the loop returns on iteration zero. Those call sites poll for
// helper symmetry, deliberately relaxing "gone now" to "gone within
// windowsPollDeadline".
//
// stage names the assertion so a bare CI line identifies which one failed.
func waitForWindowsPidGone(t *testing.T, pid uint32, stage string) {
	t.Helper()
	deadline := time.Now().Add(windowsPollDeadline)
	for time.Now().Before(deadline) {
		if !isWindowsPidAlive(pid) {
			return
		}
		time.Sleep(windowsPollInterval)
	}
	// Re-check: the loop gives back the last interval to sleep, and a process
	// that exits inside it is within the stated bound.
	if !isWindowsPidAlive(pid) {
		return
	}
	t.Fatalf("%s: process %d still running", stage, pid)
}

func waitForWindowsChild(t *testing.T, parent uint32) uint32 {
	t.Helper()
	deadline := time.Now().Add(windowsPollDeadline)
	for {
		children, err := snapshotWindowsChildProcesses()
		require.NoError(t, err, "snapshotWindowsChildProcesses")
		if kids := children[parent]; len(kids) > 0 {
			return kids[0]
		}
		if !time.Now().Before(deadline) {
			break
		}
		time.Sleep(windowsPollInterval)
	}
	t.Fatalf("child of process %d did not appear", parent)
	return 0
}
