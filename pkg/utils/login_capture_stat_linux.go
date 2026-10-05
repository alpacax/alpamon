//go:build linux

package utils

import (
	"io/fs"
	"syscall"
)

// statIdentity returns a file's inode and ctime, for the PAM file cache key.
func statIdentity(info fs.FileInfo) (uint64, int64) {
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		return st.Ino, st.Ctim.Nano()
	}
	return 0, 0
}
