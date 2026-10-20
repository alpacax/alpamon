//go:build linux

package utils

import "golang.org/x/sys/unix"

// newPrivateSocket returns a socket whose inode mode is already 0600: Linux gives a
// socket bound after fchmod that mode instead of the umask's, so it is never wider.
func newPrivateSocket() (int, error) {
	fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	if err := unix.Fchmod(fd, 0600); err != nil {
		_ = unix.Close(fd)
		return -1, err
	}
	return fd, nil
}

// setBoundSocketMode has nothing left to do: the socket was bound at 0600.
func setBoundSocketMode(string) error { return nil }
