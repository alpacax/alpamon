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

// chownTree takes ownership of fd, the open root. It holds one directory fd at a time so depth
// cannot hit the fd limit, and fails closed when ".." is not the directory it left.
func chownTree(fd int, root string, uid, gid int) (err error) {
	defer func() {
		if cerr := unix.Close(fd); cerr != nil && err == nil {
			err = fmt.Errorf("close %s: %w", root, cerr) // only a finished walk is back at root
		}
	}()

	top, err := enterDir(fd, root, uid, gid)
	if err != nil {
		return err
	}
	stack := []*dirFrame{top}
	for {
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
			fd = pfd
			dev, ino, err := dirID(fd, parent.path)
			if err != nil {
				return err
			}
			if dev != parent.dev || ino != parent.ino {
				return fmt.Errorf("%s changed while walking", parent.path)
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
			fd = cfd
			frame, err := enterDir(fd, child, uid, gid)
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
}

// enterDir chowns the directory behind fd and records its identity and entries.
func enterDir(fd int, path string, uid, gid int) (*dirFrame, error) {
	dev, ino, err := dirID(fd, path)
	if err != nil {
		return nil, err
	}
	if err := unix.Fchown(fd, uid, gid); err != nil {
		return nil, fmt.Errorf("chown %s: %w", path, err)
	}
	names, err := readDirNames(fd, path)
	if err != nil {
		return nil, err
	}
	afterReadDir(path)
	return &dirFrame{path: path, dev: dev, ino: ino, names: names}, nil
}

func dirID(fd int, path string) (dev, ino uint64, err error) {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return 0, 0, fmt.Errorf("stat %s: %w", path, err)
	}
	return uint64(st.Dev), st.Ino, nil
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
