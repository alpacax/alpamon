//go:build linux

package runner

import (
	"errors"

	"golang.org/x/sys/unix"
)

// waitExit blocks until pid exits and leaves it unreaped (WNOWAIT), so the pid stays taken.
func waitExit(pid int) error {
	var info unix.Siginfo
	for {
		err := unix.Waitid(unix.P_PID, pid, &info, unix.WEXITED|unix.WNOWAIT, nil)
		if !errors.Is(err, unix.EINTR) {
			return err
		}
	}
}
