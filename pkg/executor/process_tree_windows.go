//go:build windows

package executor

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// The steps afterStart can fail, behind variables so Windows tests can force each failure.
var (
	assignProcessToJobObject = windows.AssignProcessToJobObject
	resumeProcessThreads     = resumeThreadsOfProcess
)

var procGetProcessIdOfThread = windows.NewLazySystemDLL("kernel32.dll").NewProc("GetProcessIdOfThread")

// commandCleanup mirrors the type in process_tree_unix.go; the commandCleaner assertion below pins
// the shared afterStart/cancel/close method set across build tags. State differs per platform.
//
// Every kill goes through something this type created: the job object, or its own handle to the root.
// Never a PID: once the root exits its PID can be reused, and Windows leaves that PID in the
// ParentProcessID of every process the root ever started, so a PID-based tree walk reaches processes
// that were never part of the command.
type commandCleanup struct {
	mu       sync.Mutex
	job      windows.Handle
	handle   windows.Handle // our handle to the root; stable identity across PID reuse
	assigned bool
	canceled bool
	closed   bool
}

var _ commandCleaner = (*commandCleanup)(nil)

func configureProcessTreeCleanup(cmd *exec.Cmd, _ bool) (*commandCleanup, error) {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return nil, err
	}
	// Set at creation, not at cancel, so the tree dies with the last job handle even when Alpamon itself
	// exits without running cancel.
	if err := setKillOnJobClose(job); err != nil {
		_ = windows.CloseHandle(job)
		return nil, err
	}
	// The root starts suspended and runs only once afterStart has put it in the job, so nothing it
	// starts can run outside the job. Merged into any flags the caller already set.
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.CreationFlags |= windows.CREATE_SUSPENDED
	return &commandCleanup{job: job}, nil
}

// afterStart puts the suspended root in the job, then resumes it. On error the root may still be
// suspended, so the caller must cancel before it waits.
func (c *commandCleanup) afterStart(cmd *exec.Cmd) error {
	if cmd.Process == nil {
		return os.ErrProcessDone
	}
	canceled, err := c.attachAndResume(uint32(cmd.Process.Pid))
	if err != nil {
		return err
	}
	if canceled {
		// A cancel between Start and here had no handle of ours. The root never ran; kill it with the
		// handle now recorded, without resuming it.
		if _, err := c.cancel(cmd); err != nil && !errors.Is(err, os.ErrProcessDone) {
			return err
		}
	}
	return nil
}

// attachAndResume holds c.mu throughout, so a concurrent cancel cannot close the job or the handle while
// they are in use here; that cancel waits, then finds the root in the job.
func (c *commandCleanup) attachAndResume(pid uint32) (canceled bool, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// The only open by PID on this path, and safe: Start has returned and Wait has not, so Go's own
	// handle to the root keeps this PID from being reused. Never open a PID that nothing we hold pins.
	handle, err := windows.OpenProcess(
		windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE|windows.SYNCHRONIZE, // AssignProcessToJobObject, TerminateProcess, and WaitForSingleObject
		false, // bInheritHandles: this cleanup handle must not leak into child processes
		pid,
	)
	if err != nil {
		return c.canceled, fmt.Errorf("open command process: %w", err)
	}
	c.handle = handle
	if c.canceled {
		return true, nil
	}
	if err := assignProcessToJobObject(c.job, handle); err != nil {
		return false, fmt.Errorf("assign command process to job object: %w", err)
	}
	c.assigned = true
	if err := resumeProcessThreads(pid); err != nil {
		return false, fmt.Errorf("resume command process: %w", err)
	}
	return false, nil
}

// cancel kills the root through its handle and every other member through the job, then closes both.
// Idempotent: a second call finds no handles and kills nothing.
func (c *commandCleanup) cancel(cmd *exec.Cmd) (cleanupOutcome, error) {
	job, handle, assigned := c.takeForCancel()
	outcome := cleanupOutcome{assigned: assigned}

	var firstErr error
	keep := func(err error) {
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if assigned && job != 0 {
		active, err := queryActiveProcesses(job)
		outcome.active = active
		keep(err)
	}
	switch {
	case handle != 0:
		err := windows.TerminateProcess(handle, 1)
		if err == nil {
			outcome.rootKilled = true
		} else if !isWindowsTerminateGone(err) {
			keep(err)
		}
		keep(windows.CloseHandle(handle))
	case cmd.Process != nil:
		// No handle of ours: a cancel that raced ahead of afterStart, or an OpenProcess that failed.
		// Kill goes through Go's own handle to the root, never a PID, and after Wait it returns
		// os.ErrProcessDone without touching anything.
		err := cmd.Process.Kill()
		if err == nil {
			outcome.rootKilled = true
		} else if !errors.Is(err, os.ErrProcessDone) {
			keep(err)
		}
	}
	if job != 0 {
		// Explicit, because kill-on-close fires only when the last handle to the job closes, and any
		// other holder (a debugger, security software) would make our CloseHandle a no-op.
		keep(windows.TerminateJobObject(job, 1))
		keep(windows.CloseHandle(job))
	}
	return outcome, firstErr
}

// takeForCancel confines the locked field work so cancel's Win32 calls run lock-free; defer-released so a
// panic can't strand c.mu.
func (c *commandCleanup) takeForCancel() (windows.Handle, windows.Handle, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.canceled = true
	return c.takeJobHandleLocked(), c.takeProcessHandleLocked(), c.assigned
}

func (c *commandCleanup) close() error {
	job, handle := c.takeForClose()

	var firstErr error
	if job != 0 {
		firstErr = windows.CloseHandle(job)
	}
	if handle != 0 {
		if err := windows.CloseHandle(handle); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// Like takeForCancel: grab the handles under the lock so close's CloseHandle calls run lock-free.
func (c *commandCleanup) takeForClose() (windows.Handle, windows.Handle) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.takeJobHandleLocked(), c.takeProcessHandleLocked()
}

func (c *commandCleanup) takeProcessHandleLocked() windows.Handle {
	if c.handle == 0 {
		return 0
	}
	handle := c.handle
	c.handle = 0
	return handle
}

func (c *commandCleanup) takeJobHandleLocked() windows.Handle {
	if c.closed || c.job == 0 {
		return 0
	}
	job := c.job
	c.closed = true
	c.job = 0
	return job
}

func setKillOnJobClose(job windows.Handle) error {
	info := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	info.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	ret, err := windows.SetInformationJobObject(
		job,
		windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)),
		uint32(unsafe.Sizeof(info)),
	)
	if ret == 0 {
		if err == nil {
			return syscall.EINVAL
		}
		return err
	}
	return nil
}

// jobBasicAccounting mirrors JOBOBJECT_BASIC_ACCOUNTING_INFORMATION, which x/sys/windows does not define.
type jobBasicAccounting struct {
	TotalUserTime             int64
	TotalKernelTime           int64
	ThisPeriodTotalUserTime   int64
	ThisPeriodTotalKernelTime int64
	TotalPageFaultCount       uint32
	TotalProcesses            uint32
	ActiveProcesses           uint32
	TotalTerminatedProcesses  uint32
}

func queryActiveProcesses(job windows.Handle) (uint32, error) {
	var info jobBasicAccounting
	err := windows.QueryInformationJobObject(
		job,
		windows.JobObjectBasicAccountingInformation,
		uintptr(unsafe.Pointer(&info)),
		uint32(unsafe.Sizeof(info)),
		nil,
	)
	if err != nil {
		return 0, err
	}
	return info.ActiveProcesses, nil
}

// resumeThreadsOfProcess resumes a process started with CREATE_SUSPENDED. Go closes the thread handle
// CreateProcess returns, so the threads come from a snapshot. The caller must hold a handle to pid, which
// keeps the PID from being reused, so the threads matched by OwnerProcessID are that process's threads.
func resumeThreadsOfProcess(pid uint32) error {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPTHREAD, 0)
	if err != nil {
		return err
	}
	defer func() { _ = windows.CloseHandle(snapshot) }()

	resumed := 0
	var entry windows.ThreadEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))
	for err = windows.Thread32First(snapshot, &entry); err == nil; err = windows.Thread32Next(snapshot, &entry) {
		if entry.OwnerProcessID == pid {
			if err := resumeThreadOf(entry.ThreadID, pid); err != nil {
				return err
			}
			resumed++
		}
		entry.Size = uint32(unsafe.Sizeof(entry))
	}
	if !errors.Is(err, windows.ERROR_NO_MORE_FILES) {
		return err
	}
	if resumed == 0 {
		return fmt.Errorf("no thread of process %d in the snapshot", pid)
	}
	return nil
}

// resumeThreadOf resumes thread tid only if it still belongs to pid: a thread ID is free for reuse once
// its thread is gone, which can happen between the snapshot and the open.
func resumeThreadOf(tid, pid uint32) error {
	thread, err := windows.OpenThread(windows.THREAD_SUSPEND_RESUME|windows.THREAD_QUERY_LIMITED_INFORMATION, false, tid)
	if err != nil {
		return err
	}
	defer func() { _ = windows.CloseHandle(thread) }()
	owner, _, err := procGetProcessIdOfThread.Call(uintptr(thread))
	if owner == 0 {
		return err
	}
	if uint32(owner) != pid {
		return fmt.Errorf("thread %d no longer belongs to process %d", tid, pid)
	}
	_, err = windows.ResumeThread(thread)
	return err
}

func isWindowsProcessGone(err error) bool {
	return errors.Is(err, windows.ERROR_INVALID_PARAMETER) || errors.Is(err, windows.ERROR_NOT_FOUND)
}

// isWindowsTerminateGone treats ACCESS_DENIED as already-exited: it is what TerminateProcess returns for a process that has already ended—safe to assume only because the handle is one we opened with PROCESS_TERMINATE ourselves.
func isWindowsTerminateGone(err error) bool {
	return isWindowsProcessGone(err) || errors.Is(err, windows.ERROR_ACCESS_DENIED)
}
