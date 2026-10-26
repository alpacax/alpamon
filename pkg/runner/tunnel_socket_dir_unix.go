//go:build !windows

package runner

import (
	"errors"
	"fmt"
	"math"
	"os"
	"slices"
	"syscall"

	"golang.org/x/sys/unix"
)

// tunnelSocketDirPolicy returns the owners a pre-existing tunnel socket dir may have
// and the owner to give it; a nil owner keeps the dir's current one.
func tunnelSocketDirPolicy(daemon *syscall.Credential, euid uint32) (allowed []uint32, owner *syscall.Credential) {
	if daemon != nil {
		return []uint32{0, daemon.Uid}, daemon
	}
	return []uint32{euid}, nil
}

// credentialIDs converts cred's uid and gid for chown; macOS nobody (4294967294) fits only a 64-bit int.
func credentialIDs(cred *syscall.Credential) (int, int, error) {
	uid, gid := uint64(cred.Uid), uint64(cred.Gid)
	if uid > math.MaxInt || gid > math.MaxInt {
		return 0, 0, fmt.Errorf("uid/gid exceeds int range: uid=%d, gid=%d", uid, gid)
	}
	return int(uid), int(gid), nil
}

// secureTunnelSocketDir rejects a dir that is a symlink, not a directory, or owned by
// a uid outside allowedOwners, then forces mode 0700 and, when owner is non-nil, the owner.
// Every step runs on one open fd, so the dir cannot be swapped for a symlink in between.
func secureTunnelSocketDir(dir string, owner *syscall.Credential, allowedOwners ...uint32) error {
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
	if owner != nil {
		uid, gid, err := credentialIDs(owner)
		if err != nil {
			return err
		}
		if err := unix.Fchown(fd, uid, gid); err != nil {
			return fmt.Errorf("failed to chown tunnel socket directory: %w", err)
		}
	}
	return nil
}
