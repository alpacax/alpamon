//go:build windows

package executor

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

var (
	errForcedAssign = errors.New("forced job assignment failure")
	errForcedResume = errors.New("forced resume failure")
)

func forceAssignFailure(t *testing.T) {
	t.Helper()
	orig := assignProcessToJobObject
	assignProcessToJobObject = func(windows.Handle, windows.Handle) error { return errForcedAssign }
	t.Cleanup(func() { assignProcessToJobObject = orig })
}

func forceResumeFailure(t *testing.T) {
	t.Helper()
	orig := resumeProcessThreads
	resumeProcessThreads = func(uint32) error { return errForcedResume }
	t.Cleanup(func() { resumeProcessThreads = orig })
}

func TestConfigureProcessTreeCleanup_StartsSuspendedAndKeepsCallerFlags(t *testing.T) {
	t.Run("allocates SysProcAttr", func(t *testing.T) {
		cmd := &exec.Cmd{}
		cleanup, err := configureProcessTreeCleanup(cmd, false)
		require.NoError(t, err, "configureProcessTreeCleanup")
		defer func() { _ = cleanup.close() }()
		require.NotNil(t, cmd.SysProcAttr, "SysProcAttr was not allocated")
		assert.Equal(t, uint32(windows.CREATE_SUSPENDED), cmd.SysProcAttr.CreationFlags)
	})

	t.Run("merges into caller flags", func(t *testing.T) {
		cmd := &exec.Cmd{SysProcAttr: &syscall.SysProcAttr{HideWindow: true, CreationFlags: windows.CREATE_NEW_PROCESS_GROUP}}
		cleanup, err := configureProcessTreeCleanup(cmd, false)
		require.NoError(t, err, "configureProcessTreeCleanup")
		defer func() { _ = cleanup.close() }()
		assert.True(t, cmd.SysProcAttr.HideWindow, "HideWindow was clobbered")
		assert.Equal(t, uint32(windows.CREATE_NEW_PROCESS_GROUP|windows.CREATE_SUSPENDED), cmd.SysProcAttr.CreationFlags)
	})

	t.Run("sets kill-on-close at creation", func(t *testing.T) {
		cleanup, err := configureProcessTreeCleanup(&exec.Cmd{}, false)
		require.NoError(t, err, "configureProcessTreeCleanup")
		defer func() { _ = cleanup.close() }()
		var info windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
		err = windows.QueryInformationJobObject(cleanup.job, windows.JobObjectExtendedLimitInformation,
			uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info)), nil)
		require.NoError(t, err, "QueryInformationJobObject")
		assert.NotZero(t, info.BasicLimitInformation.LimitFlags&windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
			"JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE is not set")
	})
}

func TestCommandCleanup_CancelTerminatesViaJobAssignment(t *testing.T) {
	cmd := exec.Command("ping", "-n", "60", "127.0.0.1")
	cleanup, err := configureProcessTreeCleanup(cmd, false)
	require.NoError(t, err, "configureProcessTreeCleanup")
	defer func() { _ = cleanup.close() }()

	err = cmd.Start()
	require.NoError(t, err, "cmd.Start")
	pid := uint32(cmd.Process.Pid)

	err = cleanup.afterStart(cmd)
	require.NoError(t, err, "afterStart")
	require.True(t, cleanup.assigned, "expected the process to be assigned to the job object")

	outcome, err := cleanup.cancel(cmd)
	require.NoError(t, err, "cancel")
	assert.True(t, outcome.assigned, "outcome.assigned")
	assert.True(t, outcome.rootKilled, "outcome.rootKilled")
	assert.NotZero(t, outcome.active, "outcome.active: the running root is a job member")
	waitForCmd(t, cmd)
	waitForWindowsPidGone(t, pid, "after cancel via job assignment")
}

// The assigned job must take a descendant with it: cmd.exe -> ping, both die on cancel. Nothing but the
// root handle and the job is ever terminated, so the child dying proves it was in the job.
func TestCommandCleanup_CancelTerminatesMultiLevelTreeViaJob(t *testing.T) {
	cmd := exec.Command("cmd", "/c", "ping", "-n", "60", "127.0.0.1")
	cleanup, err := configureProcessTreeCleanup(cmd, false)
	require.NoError(t, err, "configureProcessTreeCleanup")
	defer func() { _ = cleanup.close() }()

	err = cmd.Start()
	require.NoError(t, err, "cmd.Start")
	rootPID := uint32(cmd.Process.Pid)

	err = cleanup.afterStart(cmd)
	require.NoError(t, err, "afterStart")
	require.True(t, cleanup.assigned, "expected the process to be assigned to the job object")
	childPID := waitForWindowsChild(t, rootPID, "ping.exe")

	_, err = cleanup.cancel(cmd)
	require.NoError(t, err, "cancel")
	waitForCmd(t, cmd)

	waitForWindowsPidGone(t, rootPID, "root process after cancel")
	waitForWindowsPidGone(t, childPID, "child process after cancel")
}

// Kill-on-close is set when the job is created, so closing the cleanup alone, as happens when Alpamon
// exits without running cancel, takes a multi-level tree down.
func TestCommandCleanup_CloseAloneKillsTree(t *testing.T) {
	cmd := exec.Command("cmd", "/c", "ping", "-n", "60", "127.0.0.1")
	cleanup, err := configureProcessTreeCleanup(cmd, false)
	require.NoError(t, err, "configureProcessTreeCleanup")

	err = cmd.Start()
	require.NoError(t, err, "cmd.Start")
	rootPID := uint32(cmd.Process.Pid)
	err = cleanup.afterStart(cmd)
	require.NoError(t, err, "afterStart")
	childPID := waitForWindowsChild(t, rootPID, "ping.exe")

	require.NoError(t, cleanup.close(), "close")
	waitForCmd(t, cmd)
	waitForWindowsPidGone(t, rootPID, "root process after close")
	waitForWindowsPidGone(t, childPID, "child process after close")
}

// The root runs only after it is in the job: before afterStart it starts nothing, and what it starts
// right after is a job member from the first instruction.
func TestCommandCleanup_RootStaysSuspendedUntilAssigned(t *testing.T) {
	cmd := exec.Command("cmd", "/c", "ping", "-n", "60", "127.0.0.1")
	cleanup, err := configureProcessTreeCleanup(cmd, false)
	require.NoError(t, err, "configureProcessTreeCleanup")
	defer func() { _ = cleanup.close() }()

	err = cmd.Start()
	require.NoError(t, err, "cmd.Start")
	rootPID := uint32(cmd.Process.Pid)
	t.Cleanup(func() {
		_, _ = cleanup.cancel(cmd)
		_ = cmd.Wait()
	})

	// A running cmd.exe starts ping within milliseconds; a suspended one starts nothing.
	time.Sleep(300 * time.Millisecond)
	children, err := snapshotWindowsChildProcesses()
	require.NoError(t, err, "snapshotWindowsChildProcesses")
	require.Empty(t, children[rootPID], "the root ran before afterStart")

	err = cleanup.afterStart(cmd)
	require.NoError(t, err, "afterStart")
	childPID := waitForWindowsChild(t, rootPID, "ping.exe")
	members := jobProcessIDs(t, cleanup.job)
	assert.Contains(t, members, rootPID, "root is not in the job")
	assert.Contains(t, members, childPID, "the root's child is not in the job")
}

// A root that exits as soon as it runs cannot exit before assignment any more, and its exit code still
// reaches the caller.
func TestCommandCleanup_RootThatExitsAtOnceIsAssignedAndReaped(t *testing.T) {
	cmd := exec.Command("cmd", "/c", "exit", "7")
	cleanup, err := configureProcessTreeCleanup(cmd, false)
	require.NoError(t, err, "configureProcessTreeCleanup")
	defer func() { _ = cleanup.close() }()

	err = cmd.Start()
	require.NoError(t, err, "cmd.Start")
	err = cleanup.afterStart(cmd)
	require.NoError(t, err, "afterStart")
	assert.True(t, cleanup.assigned, "a root that exits at once must still be assigned")

	err = cmd.Wait()
	var exitErr *exec.ExitError
	require.ErrorAs(t, err, &exitErr, "cmd.Wait")
	assert.Equal(t, 7, exitErr.ExitCode())

	outcome, err := cleanup.cancel(cmd)
	require.NoError(t, err, "cancel")
	assert.False(t, outcome.rootKilled, "the root had already exited")

	exitCode, _, err := NewExecutor().Execute(context.Background(), CommandOptions{
		Args: []string{"cmd", "/c", "exit", "7"},
	})
	assert.Error(t, err, "Execute")
	assert.Equal(t, 7, exitCode, "Execute exit code")
}

// Regression for the PID-based tree walk. The root starts ping outside any job and exits, so ping is
// left with ParentProcessID == the root's PID. Windows keeps that PID in an orphan's ParentProcessID and
// reuses it, so a walk from it reaches processes that are not the command's; the old cancel walked it
// and killed ping. cancel must touch only the root handle and the job, so ping has to survive.
func TestCommandCleanup_CancelSparesProcessesParentedByExitedRoot(t *testing.T) {
	forceAssignFailure(t)
	cmd := exec.Command("cmd", "/c", "start", "", "ping", "-n", "30", "127.0.0.1")
	cleanup, err := configureProcessTreeCleanup(cmd, false)
	require.NoError(t, err, "configureProcessTreeCleanup")
	defer func() { _ = cleanup.close() }()

	err = cmd.Start()
	require.NoError(t, err, "cmd.Start")
	rootPID := uint32(cmd.Process.Pid)
	err = cleanup.afterStart(cmd)
	require.ErrorIs(t, err, errForcedAssign, "afterStart")
	require.False(t, cleanup.assigned, "assignment was forced to fail")

	// Let the unassigned root run, which is the state the walk used to clean up after.
	require.NoError(t, resumeThreadsOfProcess(rootPID), "resume the root")
	orphanPID := waitForWindowsChild(t, rootPID, "ping.exe")
	orphan, err := windows.OpenProcess(windows.PROCESS_TERMINATE|windows.SYNCHRONIZE, false, orphanPID)
	require.NoError(t, err, "open the orphan")
	t.Cleanup(func() {
		_ = windows.TerminateProcess(orphan, 1)
		_ = windows.CloseHandle(orphan)
	})
	waitForCmd(t, cmd)

	outcome, err := cleanup.cancel(cmd)
	require.NoError(t, err, "cancel")
	assert.False(t, outcome.assigned, "outcome.assigned")
	assert.False(t, outcome.rootKilled, "the root had already exited")

	event, err := windows.WaitForSingleObject(orphan, 500)
	require.NoError(t, err, "WaitForSingleObject")
	assert.Equal(t, uint32(windows.WAIT_TIMEOUT), event, "cancel killed a process outside the command's job")
}

// A root whose setup failed is still suspended. Execute must kill it before Wait and fail the command,
// and the command must never have run.
func TestExecutor_SetupFailureFailsCommandWithoutRunningIt(t *testing.T) {
	for _, tc := range []struct {
		name    string
		force   func(*testing.T)
		wantErr error
	}{
		{name: "assignment", force: forceAssignFailure, wantErr: errForcedAssign},
		{name: "resume", force: forceResumeFailure, wantErr: errForcedResume},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.force(t)
			marker := filepath.Join(t.TempDir(), "ran")

			type result struct {
				exitCode int
				err      error
			}
			done := make(chan result, 1)
			go func() {
				exitCode, _, err := NewExecutor().Execute(context.Background(), CommandOptions{
					Args: []string{"cmd", "/c", "mkdir", marker},
				})
				done <- result{exitCode: exitCode, err: err}
			}()

			var res result
			select {
			case res = <-done:
			case <-time.After(10 * time.Second):
				t.Fatal("Execute did not return; the suspended root was not killed before Wait")
			}
			assert.Equal(t, 1, res.exitCode, "exit code")
			assert.ErrorIs(t, res.err, tc.wantErr, "Execute error")
			_, err := os.Stat(marker)
			assert.ErrorIs(t, err, os.ErrNotExist, "the command ran although its setup failed")
		})
	}
}

// cancel racing ahead of afterStart: the raced cancel kills the suspended root through Go's own handle,
// and afterStart must notice canceled==true and redo the cancel instead of resuming it.
func TestCommandCleanup_AfterStartReCancelsWhenAlreadyCanceled(t *testing.T) {
	cmd := exec.Command("ping", "-n", "60", "127.0.0.1")
	cleanup, err := configureProcessTreeCleanup(cmd, false)
	require.NoError(t, err, "configureProcessTreeCleanup")
	defer func() { _ = cleanup.close() }()

	err = cmd.Start()
	require.NoError(t, err, "cmd.Start")
	pid := uint32(cmd.Process.Pid)

	_, err = cleanup.cancel(cmd)
	require.NoError(t, err, "first cancel")
	require.True(t, cleanup.canceled, "expected canceled to be set after cancel")
	err = cleanup.afterStart(cmd)
	require.NoError(t, err, "afterStart")
	assert.False(t, cleanup.assigned, "a canceled root must not be assigned and resumed")
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
	defer func() { _ = windows.CloseHandle(h) }()
	event, err := windows.WaitForSingleObject(h, 0)
	return err == nil && event == uint32(windows.WAIT_TIMEOUT)
}

// waitForWindowsPidGone fails only if pid is still alive after a bounded wait.
// cancel() tears the tree down asynchronously (TerminateProcess on the root,
// TerminateJobObject on the rest), and waitForCmd only proves the root was
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

// waitForWindowsChild returns the first child of parent whose image is image, so a console host that
// Windows may start for the child is never mistaken for it.
func waitForWindowsChild(t *testing.T, parent uint32, image string) uint32 {
	t.Helper()
	deadline := time.Now().Add(windowsPollDeadline)
	for {
		children, err := snapshotWindowsChildProcesses()
		require.NoError(t, err, "snapshotWindowsChildProcesses")
		for _, kid := range children[parent] {
			if strings.EqualFold(kid.image, image) {
				return kid.pid
			}
		}
		if !time.Now().Before(deadline) {
			break
		}
		time.Sleep(windowsPollInterval)
	}
	t.Fatalf("%s child of process %d did not appear", image, parent)
	return 0
}

type windowsChildProcess struct {
	pid   uint32
	image string
}

// snapshotWindowsChildProcesses maps ParentProcessID to children. Test-only: production code must never
// find processes this way (see process_tree_guard_test.go).
func snapshotWindowsChildProcesses() (map[uint32][]windowsChildProcess, error) {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, err
	}
	defer func() { _ = windows.CloseHandle(snapshot) }()

	children := map[uint32][]windowsChildProcess{}
	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))
	if err := windows.Process32First(snapshot, &entry); err != nil {
		if errors.Is(err, windows.ERROR_NO_MORE_FILES) {
			return children, nil
		}
		return nil, err
	}
	for {
		children[entry.ParentProcessID] = append(children[entry.ParentProcessID], windowsChildProcess{
			pid:   entry.ProcessID,
			image: windows.UTF16ToString(entry.ExeFile[:]),
		})
		entry.Size = uint32(unsafe.Sizeof(entry))
		err := windows.Process32Next(snapshot, &entry)
		if err == nil {
			continue
		}
		if errors.Is(err, windows.ERROR_NO_MORE_FILES) {
			return children, nil
		}
		return nil, err
	}
}

// jobProcessIDList mirrors JOBOBJECT_BASIC_PROCESS_ID_LIST with room for more members than any test starts.
type jobProcessIDList struct {
	NumberOfAssignedProcesses uint32
	NumberOfProcessIdsInList  uint32
	ProcessIdList             [64]uintptr
}

func jobProcessIDs(t *testing.T, job windows.Handle) []uint32 {
	t.Helper()
	var list jobProcessIDList
	err := windows.QueryInformationJobObject(job, windows.JobObjectBasicProcessIdList,
		uintptr(unsafe.Pointer(&list)), uint32(unsafe.Sizeof(list)), nil)
	require.NoError(t, err, "QueryInformationJobObject(JobObjectBasicProcessIdList)")
	ids := make([]uint32, 0, list.NumberOfProcessIdsInList)
	for _, id := range list.ProcessIdList[:list.NumberOfProcessIdsInList] {
		ids = append(ids, uint32(id))
	}
	return ids
}
