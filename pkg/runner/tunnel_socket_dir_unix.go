//go:build !windows

package runner

import (
	"fmt"
	"os"
	"slices"
	"syscall"
)

// secureTunnelSocketDir rejects a dir that is a symlink, not a directory, or owned by
// a uid outside allowedOwners, then forces mode 0700 so a pre-made dir cannot stay open.
func secureTunnelSocketDir(dir string, allowedOwners ...uint32) error {
	fi, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("failed to stat tunnel socket directory: %w", err)
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing symlink at %s", dir)
	}
	if !fi.IsDir() {
		return fmt.Errorf("%s is not a directory", dir)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("cannot determine owner of %s", dir)
	}
	if !slices.Contains(allowedOwners, st.Uid) {
		return fmt.Errorf("%s is owned by uid %d, which is not allowed", dir, st.Uid)
	}
	if err := os.Chmod(dir, 0700); err != nil {
		return fmt.Errorf("failed to restrict tunnel socket directory: %w", err)
	}
	return nil
}
