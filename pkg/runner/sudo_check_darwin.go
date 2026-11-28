package runner

import "golang.org/x/sys/unix"

func sudoProcessStart(pid int) uint64 {
	info, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if err != nil {
		return 0
	}
	return uint64(info.Proc.P_starttime.Nano())
}
