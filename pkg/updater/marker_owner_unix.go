//go:build !windows

package updater

import (
	"fmt"
	"os"
	"syscall"
)

// checkMarkerOwner accepts a marker owned by this process's user and not
// writable by group or others.
func checkMarkerOwner(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("upgrade marker is not a regular file")
	}
	if info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("upgrade marker is writable by group or others")
	}
	if st, ok := info.Sys().(*syscall.Stat_t); ok && int(st.Uid) != os.Geteuid() {
		return fmt.Errorf("upgrade marker is owned by uid %d", st.Uid)
	}
	return nil
}
