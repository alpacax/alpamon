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

// Tests swap these hooks in to race the walk.
var (
	afterReadDir  = func(dir string) {}
	beforeOpenDir = func(child string) {} // after the stat, before the open
)

type dirFrame struct {
	path  string
	dev   uint64
	ino   uint64
	names []string
}

// ChownRecursive changes the owner of path and everything under it. Symlinks inside the
// tree and at path itself are left alone; path's parent directories resolve as usual.
// Entries removed while the walk runs are skipped. On error, entries already
// chowned keep their new owner.
func ChownRecursive(path string, uid, gid int) error {
	if path == "" {
		return errors.New("path must not be empty")
	}
	path = filepath.Clean(path)

	// Open first: a stat before it would leave a window to swap the root.
	fd, err := unix.Open(path, openDirFlags, 0)
	if err == nil {
		return chownTree(fd, path, uid, gid)
	}
	if !errors.Is(err, unix.ENOTDIR) && !errors.Is(err, unix.ELOOP) {
		return &os.PathError{Op: "open", Path: path, Err: err}
	}
	info, lerr := os.Lstat(path) // Linux reports a symlink to a file as ENOTDIR
	switch {
	case lerr != nil:
		return lerr
	case info.Mode()&os.ModeSymlink != 0:
		return nil
	case !info.IsDir():
		return os.Lchown(path, uid, gid)
	}
	return &os.PathError{Op: "open", Path: path, Err: err} // became a directory after the open
}

// chownTree takes ownership of fd, the open root directory. Only the current
// directory's fd stays open, so a deep tree cannot exhaust the fd limit: the walk
// climbs back through ".." and fails closed when that is not the directory it left.
func chownTree(fd int, path string, uid, gid int) (err error) {
	defer func() {
		if cerr := unix.Close(fd); cerr != nil && err == nil {
			err = fmt.Errorf("close %s: %w", path, cerr)
		}
	}()

	top, err := enterDir(fd, path, uid, gid)
	if err != nil {
		return err
	}
	stack := []*dirFrame{top}
	for len(stack) > 0 {
		cur := stack[len(stack)-1]
		if len(cur.names) == 0 {
			stack = stack[:len(stack)-1]
			if len(stack) == 0 {
				return nil
			}
			parent := stack[len(stack)-1]
			pfd, err := unix.Openat(fd, "..", openDirFlags, 0)
			if err != nil {
				return fmt.Errorf("open %s: %w", parent.path, err)
			}
			_ = unix.Close(fd)
			fd, path = pfd, parent.path
			if err := sameDir(fd, parent); err != nil {
				return err
			}
			continue
		}

		name := cur.names[0]
		cur.names = cur.names[1:]
		child := filepath.Join(cur.path, name)

		var st unix.Stat_t
		if err := unix.Fstatat(fd, name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			if errors.Is(err, unix.ENOENT) {
				continue
			}
			return fmt.Errorf("stat %s: %w", child, err)
		}
		switch uint32(st.Mode) & unix.S_IFMT {
		case unix.S_IFLNK:
			continue
		case unix.S_IFDIR:
			beforeOpenDir(child)
			cfd, err := unix.Openat(fd, name, openDirFlags, 0)
			if err != nil {
				if errors.Is(err, unix.ENOENT) {
					continue
				}
				return fmt.Errorf("open %s: %w", child, err) // ELOOP or ENOTDIR: replaced, fail closed
			}
			_ = unix.Close(fd)
			fd, path = cfd, child
			frame, err := enterDir(fd, path, uid, gid)
			if err != nil {
				return err
			}
			stack = append(stack, frame)
		default:
			err := unix.Fchownat(fd, name, uid, gid, unix.AT_SYMLINK_NOFOLLOW)
			if err != nil && !errors.Is(err, unix.ENOENT) {
				return fmt.Errorf("chown %s: %w", child, err)
			}
		}
	}
	return nil
}

// enterDir chowns the directory behind fd and records its identity and entries.
func enterDir(fd int, path string, uid, gid int) (*dirFrame, error) {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return nil, fmt.Errorf("stat %s: %w", path, err)
	}
	if err := unix.Fchown(fd, uid, gid); err != nil {
		return nil, fmt.Errorf("chown %s: %w", path, err)
	}
	names, err := readDirNames(fd, path)
	if err != nil {
		return nil, err
	}
	afterReadDir(path)
	return &dirFrame{path: path, dev: uint64(st.Dev), ino: st.Ino, names: names}, nil
}

func sameDir(fd int, want *dirFrame) error {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return fmt.Errorf("stat %s: %w", want.path, err)
	}
	if uint64(st.Dev) != want.dev || st.Ino != want.ino {
		return fmt.Errorf("%s changed while walking", want.path)
	}
	return nil
}

// readDirNames lists the directory behind fd through a fresh descriptor, because
// os.File takes ownership of the fd it wraps and the walk closes fd itself.
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
