package commandcancel

import "golang.org/x/sys/unix"

// WaitExited observes exit without reaping, keeping the process group identity pinned.
func WaitExited(pid int) error {
	var info unix.Siginfo
	for {
		err := unix.Waitid(unix.P_PID, pid, &info, unix.WEXITED|unix.WNOWAIT, nil)
		if err != unix.EINTR {
			return err
		}
	}
}
