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

// O_NONBLOCK keeps a FIFO from waiting for a writer; O_NOFOLLOW makes a symlink ELOOP.
const openFileFlags = unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_NONBLOCK | unix.O_CLOEXEC

// Tests swap these hooks in to race the walk.
var (
	afterReadDir = func(dir string) {}
	beforeOpen   = func(child string) {} // after the stat, before the open
)

type dirFrame struct {
	path  string
	dev   uint64
	ino   uint64
	names []string
}

// ChownRecursive changes the owner of path and everything under it. Symlinks inside the
// tree and at path itself are left alone; path's parent directories resolve as usual.
// A file under path with more than one hard link may share its inode with a file outside
// the tree, so it is chowned only when linkOwner owns it; -1 skips every such file.
// Sockets are skipped. Entries removed while the walk runs are skipped. On error, entries
// already chowned keep their new owner.
func ChownRecursive(path string, uid, gid, linkOwner int) error {
	if path == "" {
		return errors.New("path must not be empty")
	}
	path = filepath.Clean(path)

	// Open first: a stat before it would leave a window to swap the root.
	fd, err := unix.Open(path, openDirFlags, 0)
	if err == nil {
		return chownTree(fd, path, uid, gid, linkOwner)
	}
	if !errors.Is(err, unix.ENOTDIR) && !errors.Is(err, unix.ELOOP) {
		return &os.PathError{Op: "open", Path: path, Err: err}
	}
	// Not a directory, and Linux reports a symlink to a file as ENOTDIR: treat it as a file in the tree.
	var st unix.Stat_t
	if serr := unix.Fstatat(unix.AT_FDCWD, path, &st, unix.AT_SYMLINK_NOFOLLOW); serr != nil {
		return &os.PathError{Op: "stat", Path: path, Err: serr}
	}
	switch uint32(st.Mode) & unix.S_IFMT {
	case unix.S_IFLNK:
		return nil
	case unix.S_IFDIR:
		return &os.PathError{Op: "open", Path: path, Err: err} // became a directory after the open
	}
	if err := chownFile(unix.AT_FDCWD, path, &st, uid, gid, linkOwner); err != nil {
		return &os.PathError{Op: "chown", Path: path, Err: err}
	}
	return nil
}

// chownTree takes ownership of fd, the open root. It holds one directory fd at a time so depth
// cannot hit the fd limit, and fails closed when ".." is not the directory it left.
func chownTree(fd int, root string, uid, gid, linkOwner int) (err error) {
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
			beforeOpen(child)
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
			beforeOpen(child)
			if err := chownFile(fd, name, &st, uid, gid, linkOwner); err != nil {
				return fmt.Errorf("chown %s: %w", child, err)
			}
		}
	}
}

// chownFile chowns a non-directory through its own descriptor, so the inode whose link
// count was checked is the one chowned. st holds the walk's stat of name.
func chownFile(dirfd int, name string, st *unix.Stat_t, uid, gid, linkOwner int) error {
	fd, err := unix.Openat(dirfd, name, openFileFlags, 0)
	switch {
	case err == nil:
		defer func() { _ = unix.Close(fd) }()
		if err := unix.Fstat(fd, st); err != nil {
			return err
		}
		if !mayChown(st, linkOwner) {
			return nil
		}
		return unix.Fchown(fd, uid, gid)
	case errors.Is(err, unix.ENOENT), errors.Is(err, unix.ELOOP):
		return nil // removed, or swapped for a symlink
	case errors.Is(err, unix.ENXIO), errors.Is(err, unix.EOPNOTSUPP):
		return nil // a socket: Linux and macOS refuse to open one with these
	case errors.Is(err, unix.EACCES):
		// Only a non-root walk is refused, and it can chown nothing but its own files.
		if !mayChown(st, linkOwner) {
			return nil
		}
		if err := unix.Fchownat(dirfd, name, uid, gid, unix.AT_SYMLINK_NOFOLLOW); err != nil &&
			!errors.Is(err, unix.ENOENT) {
			return err
		}
		return nil
	}
	return err
}

func mayChown(st *unix.Stat_t, linkOwner int) bool {
	return st.Nlink <= 1 || int64(st.Uid) == int64(linkOwner)
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
