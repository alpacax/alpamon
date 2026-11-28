package runner

import "golang.org/x/sys/unix"

func sudoProcessStart(pid int) (start uint64, absent bool) {
	records, err := unix.SysctlKinfoProcSlice("kern.proc.pid", pid)
	if err != nil {
		return 0, false
	}
	if len(records) == 0 {
		return 0, true
	}
	return uint64(records[0].Proc.P_starttime.Nano()), false
}
