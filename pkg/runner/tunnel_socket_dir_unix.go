//go:build !windows

package runner

import (
	"errors"
	"fmt"
	"os"
	"slices"

	"golang.org/x/sys/unix"
)

// tunnelSocketDirPolicy returns the owners a pre-existing tunnel socket dir may have
// and the owner to give it; chownUID is -1 when the dir keeps its owner.
func tunnelSocketDirPolicy(isRoot bool, euid uint32, nobodyUID, nobodyGID int) (allowed []uint32, chownUID, chownGID int) {
	if isRoot {
		return []uint32{0, uint32(nobodyUID)}, nobodyUID, nobodyGID
	}
	return []uint32{euid}, -1, -1
}

// secureTunnelSocketDir rejects a dir that is a symlink, not a directory, or owned by
// a uid outside allowedOwners, then forces mode 0700 and, when chownUID >= 0, the owner.
// Every step runs on one open fd, so the dir cannot be swapped for a symlink in between.
func secureTunnelSocketDir(dir string, chownUID, chownGID int, allowedOwners ...uint32) error {
	fd, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, unix.ELOOP) {
			return fmt.Errorf("refusing symlink at %s", dir)
		}
		if errors.Is(err, unix.ENOTDIR) {
			// O_DIRECTORY|O_NOFOLLOW reports a symlink as ENOTDIR on some kernels; Lstat only words the error.
			if fi, lerr := os.Lstat(dir); lerr == nil && fi.Mode()&os.ModeSymlink != 0 {
				return fmt.Errorf("refusing symlink at %s", dir)
			}
			return fmt.Errorf("%s is not a directory", dir)
		}
		return fmt.Errorf("failed to open tunnel socket directory: %w", err)
	}
	defer func() { _ = unix.Close(fd) }()

	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return fmt.Errorf("failed to stat tunnel socket directory: %w", err)
	}
	if !slices.Contains(allowedOwners, st.Uid) {
		return fmt.Errorf("%s is owned by uid %d, which is not allowed", dir, st.Uid)
	}
	if err := unix.Fchmod(fd, 0700); err != nil {
		return fmt.Errorf("failed to restrict tunnel socket directory: %w", err)
	}
	if chownUID >= 0 {
		if err := unix.Fchown(fd, chownUID, chownGID); err != nil {
			return fmt.Errorf("failed to chown tunnel socket directory: %w", err)
		}
	}
	return nil
}
