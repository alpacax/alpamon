//go:build unix

package user

import (
	"fmt"
	"os"
	"syscall"
)

func fileOwnerUID(info os.FileInfo) (uint64, error) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, fmt.Errorf("failed to read owner of %s", info.Name())
	}
	return uint64(stat.Uid), nil
}
