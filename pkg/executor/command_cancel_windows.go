package executor

import (
	"errors"
	"fmt"
	"os/exec"
	"slices"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

func (c *commandCleanup) cancelRemote(cmd *exec.Cmd, _ time.Duration) (cleanupOutcome, error) {
	job, duplicateErr := c.duplicateJob()
	if job != 0 {
		defer windows.CloseHandle(job)
	}
	outcome, err := c.cancel(cmd)
	if job == 0 {
		return outcome, errors.Join(err, duplicateErr)
	}
	deadline := time.Now().Add(100 * time.Millisecond)
	for {
		pids, queryErr := queryJobProcessIDs(job)
		outcome.survivors = pids
		if len(pids) == 0 || queryErr != nil || !time.Now().Before(deadline) {
			return outcome, errors.Join(err, queryErr)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func (c *commandCleanup) duplicateJob() (windows.Handle, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.job == 0 {
		return 0, nil
	}
	var job windows.Handle
	err := windows.DuplicateHandle(windows.CurrentProcess(), c.job, windows.CurrentProcess(), &job, 0, false, windows.DUPLICATE_SAME_ACCESS)
	return job, err
}

func queryJobProcessIDs(job windows.Handle) ([]int, error) {
	for capacity := 256; capacity <= 1<<20; capacity *= 2 {
		// Two DWORD counts precede the pointer-sized PID array on both architectures.
		buffer := make([]uintptr, capacity+2)
		err := windows.QueryInformationJobObject(job, windows.JobObjectBasicProcessIdList, uintptr(unsafe.Pointer(&buffer[0])), uint32(len(buffer))*uint32(unsafe.Sizeof(buffer[0])), nil)
		if errors.Is(err, windows.ERROR_MORE_DATA) {
			continue
		}
		if err != nil {
			return nil, err
		}
		count := *(*uint32)(unsafe.Add(unsafe.Pointer(&buffer[0]), 4))
		first := unsafe.Add(unsafe.Pointer(&buffer[0]), 8)
		ids := unsafe.Slice((*uintptr)(first), int(count))
		pids := make([]int, len(ids))
		for i, id := range ids {
			pids[i] = int(id)
		}
		slices.Sort(pids)
		return pids, nil
	}
	return nil, fmt.Errorf("job process list exceeded capacity")
}

func watchCommandExit(cmd *exec.Cmd, c *commandCleanup) (<-chan error, error) {
	c.mu.Lock()
	var handle windows.Handle
	err := windows.DuplicateHandle(windows.CurrentProcess(), c.handle, windows.CurrentProcess(), &handle, 0, false, windows.DUPLICATE_SAME_ACCESS)
	c.mu.Unlock()
	if err != nil {
		return nil, err
	}
	done := make(chan error, 1)
	go func() {
		defer windows.CloseHandle(handle)
		_, err := windows.WaitForSingleObject(handle, windows.INFINITE)
		done <- err
	}()
	return done, nil
}
