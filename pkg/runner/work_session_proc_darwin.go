package runner

import "golang.org/x/sys/unix"

// Process states of kinfo_proc p_stat (sys/proc.h).
const (
	darwinStopped = 4 // SSTOP
	darwinZombie  = 5 // SZOMB
)

// processState reads the state of pid from the kernel process table.
func processState(pid int) (procState, error) {
	info, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if err != nil {
		return procRunning, err
	}
	switch info.Proc.P_stat {
	case darwinStopped:
		return procStopped, nil
	case darwinZombie:
		return procZombie, nil
	}
	return procRunning, nil
}
