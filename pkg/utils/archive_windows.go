//go:build windows

package utils

import (
	"errors"

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
