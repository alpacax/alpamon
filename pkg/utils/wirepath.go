package utils

import (
	"path/filepath"
	"runtime"
)

// Wire format for paths exchanged with the Alpacon web client is
// POSIX-like with a leading "/".
//   Unix native   "/home/foo"           <=> wire "/home/foo"
//   Windows native "C:\\Users\\foo"     <=> wire "/C:/Users/foo"
// The web client tokenizes paths on "/", so all paths sent over the
// alpacon protocol use this format. Alpamon converts to the native
// OS format before making file system calls and back to wire format
// before sending responses.

// FromWirePath converts a wire-format path to a native OS path.
// It is a no-op on Unix. On Windows, "/C:/Users/foo" → "C:\\Users\\foo".
// A bare "/C:" is normalized to the drive root "C:\\" since "C:"
// alone is drive-relative on Windows, not what a breadcrumb click to
// the drive letter means.
func FromWirePath(p string) string {
	if p == "" {
		return p
	}
	if runtime.GOOS == "windows" && len(p) >= 3 && p[0] == '/' && isWireDriveLetter(p[1], p[2]) {
		p = p[1:]
		if len(p) == 2 {
			p += `\`
		}
	}
	return filepath.FromSlash(p)
}

// ToWirePath converts a native OS path to the wire format.
// It is a no-op on Unix. On Windows, "C:\\Users\\foo" → "/C:/Users/foo".
func ToWirePath(p string) string {
	if p == "" {
		return p
	}
	slashed := filepath.ToSlash(p)
	if runtime.GOOS == "windows" && len(slashed) >= 2 && isWireDriveLetter(slashed[0], slashed[1]) {
		return "/" + slashed
	}
	return slashed
}

func isWireDriveLetter(c0, c1 byte) bool {
	return ((c0 >= 'a' && c0 <= 'z') || (c0 >= 'A' && c0 <= 'Z')) && c1 == ':'
}
