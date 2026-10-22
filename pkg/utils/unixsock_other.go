//go:build !windows && !linux

package utils

import (
	"syscall"

	"golang.org/x/sys/unix"
)

// newPrivateSocket returns an unbound socket. fchmod on a socket fails here, so
// setBoundSocketMode narrows the mode after bind, while nothing can connect yet.
func newPrivateSocket() (int, error) {
	syscall.ForkLock.RLock() // No SOCK_CLOEXEC: keep a concurrent fork from inheriting fd.
	defer syscall.ForkLock.RUnlock()
	fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		return -1, err
	}
	unix.CloseOnExec(fd)
	return fd, nil
}

func setBoundSocketMode(path string) error {
	return unix.Fchmodat(unix.AT_FDCWD, path, 0600, unix.AT_SYMLINK_NOFOLLOW)
}
