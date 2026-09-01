//go:build !windows

package utils

import (
	"os"
	"syscall"
)

// symlinkUnsupported reports whether os.Symlink failed because the host makes no
// links at all. Nothing on Unix says only that: EPERM covers a filesystem without
// link support and a plain permission denial alike.
func symlinkUnsupported(error) bool { return false }

// noFollow makes an open refuse a link sitting at the final path component:
// createFile so an entry is not written through one, OpenIfZip so the extract
// source is the file that was checked. It covers that component only.
const noFollow = syscall.O_NOFOLLOW

// chmodDir sets mode on the directory at path without following a link that
// may have taken its place since it was checked: a handle opened with
// O_NOFOLLOW is the directory itself, and fchmod acts on the handle.
func chmodDir(path string, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_DIRECTORY, 0)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	return f.Chmod(mode)
}
