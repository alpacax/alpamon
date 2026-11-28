package commandgroup

import (
	"strconv"

	"golang.org/x/sys/unix"
)

func RealUID(pid int) string {
	info, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if err != nil {
		return ""
	}
	return realUID(info)
}

func realUID(info *unix.KinfoProc) string {
	return strconv.FormatUint(uint64(info.Eproc.Pcred.P_ruid), 10)
}
