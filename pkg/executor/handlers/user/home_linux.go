package user

import (
	"fmt"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

func fileOwnerUID(info os.FileInfo) (uint64, error) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, fmt.Errorf("failed to read owner of %s", info.Name())
	}
	return uint64(stat.Uid), nil
}

func renameHome(home, destination string) error {
	return unix.Renameat2(unix.AT_FDCWD, home, unix.AT_FDCWD, destination, unix.RENAME_NOREPLACE)
}
