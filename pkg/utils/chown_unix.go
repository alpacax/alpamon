//go:build !windows

package utils

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

const openDirFlags = unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC

// ChownRecursive changes the owner of path and everything under it. It never
// follows a symlink: links inside the tree are skipped, and a symlink path is left alone.
func ChownRecursive(path string, uid, gid int) error {
	if path == "" {
		return fmt.Errorf("path must not be empty")
	}
	path = filepath.Clean(path)

	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil
	}
	if !info.IsDir() {
		if err := unix.Fchownat(unix.AT_FDCWD, path, uid, gid, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			return fmt.Errorf("chown %s: %w", path, err)
		}
		return nil
	}

	fd, err := unix.Open(path, openDirFlags, 0)
	if err != nil {
		return fmt.Errorf("open %s: %w", path, err)
	}
	return chownDirFd(fd, path, uid, gid)
}

// chownDirFd takes ownership of fd and closes it. Every step is relative to an
// open fd, so a swap after the directory was listed cannot redirect root's chown.
func chownDirFd(fd int, path string, uid, gid int) (err error) {
	defer func() {
		if cerr := unix.Close(fd); cerr != nil && err == nil {
			err = fmt.Errorf("close %s: %w", path, cerr)
		}
	}()

	if err := unix.Fchown(fd, uid, gid); err != nil {
		return fmt.Errorf("chown %s: %w", path, err)
	}

	names, err := readDirNames(fd, path)
	if err != nil {
		return err
	}

	for _, name := range names {
		child := filepath.Join(path, name)

		var st unix.Stat_t
		if err := unix.Fstatat(fd, name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			return fmt.Errorf("stat %s: %w", child, err)
		}

		switch uint32(st.Mode) & unix.S_IFMT {
		case unix.S_IFLNK:
			continue
		case unix.S_IFDIR:
			cfd, err := unix.Openat(fd, name, openDirFlags, 0)
			if err != nil {
				if errors.Is(err, unix.ELOOP) || errors.Is(err, unix.ENOTDIR) {
					// Replaced after the stat: fail closed instead of retrying.
					return fmt.Errorf("%s changed while walking: %w", child, err)
				}
				return fmt.Errorf("open %s: %w", child, err)
			}
			if err := chownDirFd(cfd, child, uid, gid); err != nil {
				return err
			}
		default:
			if err := unix.Fchownat(fd, name, uid, gid, unix.AT_SYMLINK_NOFOLLOW); err != nil {
				return fmt.Errorf("chown %s: %w", child, err)
			}
		}
	}
	return nil
}

// readDirNames lists the directory behind fd through a fresh descriptor, so
// the caller's fd keeps its own offset and is never reopened by name.
func readDirNames(fd int, path string) ([]string, error) {
	lfd, err := unix.Openat(fd, ".", openDirFlags, 0)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	f := os.NewFile(uintptr(lfd), path)
	defer func() { _ = f.Close() }()

	names, err := f.Readdirnames(-1)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	return names, nil
}
