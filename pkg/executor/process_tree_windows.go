//go:build windows

package executor

import (
	"errors"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// commandCleanup mirrors the type in process_tree_unix.go; runCommand (executor.go) consumes
// the same afterStart/cancel/close method set, unenforced across build tags, so keep the two in sync.
type commandCleanup struct {
	mu       sync.Mutex
	job      windows.Handle
	handle   windows.Handle // retained handle to the root process; stable identity across PID reuse
	pid      uint32
	assigned bool
	canceled bool
	closed   bool
}

func configureProcessTreeCleanup(_ *exec.Cmd, _ bool) (*commandCleanup, error) {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return nil, err
	}
	return &commandCleanup{job: job}, nil
}

func (c *commandCleanup) afterStart(cmd *exec.Cmd) error {
	if cmd.Process == nil {
		return os.ErrProcessDone
	}
	// A cancel between Start and here saw no job/handle yet, so its kill missed; redo it now that we hold them.
	if canceled := c.assignForStart(uint32(cmd.Process.Pid)); canceled {
		return c.cancel(cmd)
	}
	return nil
}

// Locked only here (defer-released) so afterStart can re-enter cancel without deadlocking c.mu, and a tryAssignToJob panic can't strand the lock.
func (c *commandCleanup) assignForStart(pid uint32) (canceled bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pid = pid
	c.assigned = c.tryAssignToJob(pid)
	return c.canceled
}

// tryAssignToJob returning false isn't fatal to the command: cancel falls back to the PID-based tree walk.
func (c *commandCleanup) tryAssignToJob(pid uint32) bool {
	handle, err := windows.OpenProcess(
		windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE,
		false, // bInheritHandles: this cleanup handle must not leak into child processes
		pid,
	)
	if err != nil {
		return false
	}
	c.handle = handle

	return windows.AssignProcessToJobObject(c.job, handle) == nil
}

func (c *commandCleanup) cancel(cmd *exec.Cmd) error {
	var pid uint32
	if cmd.Process != nil {
		pid = uint32(cmd.Process.Pid)
	}
	pid, job, handle := c.takeForCancel(pid)

	var firstErr error
	if job != 0 {
		if err := setKillOnJobClose(job); err != nil {
			firstErr = err
		}
		if err := windows.CloseHandle(job); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if handle != 0 {
		// Unlike the PID-based terminate below, this handle can't have been reused by an unrelated process.
		if err := windows.TerminateProcess(handle, 1); err != nil && !isWindowsTerminateGone(err) && firstErr == nil {
			firstErr = err
		}
		if err := windows.CloseHandle(handle); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if pid != 0 {
		if err := terminateWindowsProcessTree(pid); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// Confines the locked field work so cancel's slow Win32 kills run lock-free; defer-released so a panic can't strand c.mu.
func (c *commandCleanup) takeForCancel(pid uint32) (uint32, windows.Handle, windows.Handle) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.canceled = true
	if pid == 0 {
		pid = c.pid
	}
	var job windows.Handle
	if c.assigned {
		job = c.takeJobHandleLocked()
	}
	return pid, job, c.takeProcessHandleLocked()
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

func terminateWindowsProcessTree(rootPID uint32) error {
	children, err := snapshotWindowsChildProcesses()
	if err != nil {
		return err
	}

	var firstErr error
	visited := map[uint32]bool{}
	var terminate func(pid uint32)
	terminate = func(pid uint32) {
		if visited[pid] {
			return
		}
		visited[pid] = true
		for _, child := range children[pid] {
			terminate(child)
		}
		if err := terminateWindowsProcess(pid); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	terminate(rootPID)
	return firstErr
}

func snapshotWindowsChildProcesses() (map[uint32][]uint32, error) {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(snapshot)

	children := map[uint32][]uint32{}
	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))
	if err := windows.Process32First(snapshot, &entry); err != nil {
		if errors.Is(err, windows.ERROR_NO_MORE_FILES) {
			return children, nil
		}
		return nil, err
	}
	for {
		children[entry.ParentProcessID] = append(children[entry.ParentProcessID], entry.ProcessID)
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

func terminateWindowsProcess(pid uint32) error {
	handle, err := windows.OpenProcess(windows.PROCESS_TERMINATE, false, pid)
	if err != nil {
		if isWindowsProcessGone(err) {
			return nil
		}
		return err
	}
	defer windows.CloseHandle(handle)
	if err := windows.TerminateProcess(handle, 1); err != nil && !isWindowsTerminateGone(err) {
		return err
	}
	return nil
}

func isWindowsProcessGone(err error) bool {
	return errors.Is(err, windows.ERROR_INVALID_PARAMETER) || errors.Is(err, windows.ERROR_NOT_FOUND)
}

// isWindowsTerminateGone treats ACCESS_DENIED as already-exited: Windows' actual signal when the target died first (e.g. to KILL_ON_JOB_CLOSE) — safe to assume only because we just opened this handle with PROCESS_TERMINATE ourselves.
func isWindowsTerminateGone(err error) bool {
	return isWindowsProcessGone(err) || errors.Is(err, windows.ERROR_ACCESS_DENIED)
}
