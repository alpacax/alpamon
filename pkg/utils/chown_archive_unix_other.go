//go:build !linux && !windows

package utils

import "golang.org/x/sys/unix"

func openChownChild(fd int, name string, flags int, _ bool) (int, error) {
	return unix.Openat(fd, name, flags, 0)
}

func statChownChild(fd int, name string, stat *unix.Stat_t, _ bool) error {
	return unix.Fstatat(fd, name, stat, unix.AT_SYMLINK_NOFOLLOW)
}
