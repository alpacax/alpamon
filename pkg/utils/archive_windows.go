//go:build windows

package utils

import (
	"errors"
	"os"

	"golang.org/x/sys/windows"
)

// symlinkUnsupported reports whether os.Symlink failed because this host makes no
// links: no SeCreateSymbolicLink with developer mode off, or a filesystem without
// link support. Neither says anything about the archive.
func symlinkUnsupported(err error) bool {
	return errors.Is(err, windows.ERROR_PRIVILEGE_NOT_HELD) ||
		errors.Is(err, windows.ERROR_NOT_SUPPORTED) ||
		errors.Is(err, windows.ERROR_INVALID_FUNCTION)
}

// noFollow is empty: Windows has no O_NOFOLLOW, so a link put at a path
// between a check and the open that follows it is followed.
const noFollow = 0

// chmodDir sets mode on the directory at path. Windows has no O_NOFOLLOW to
// pin the handle to the directory itself, and os.Chmod there only toggles the
// read-only attribute, so there is no mode to misplace.
func chmodDir(path string, mode os.FileMode) error {
	return os.Chmod(path, mode)
}
