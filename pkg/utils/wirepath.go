package utils

import (
	"fmt"
	"path/filepath"
	"runtime"
	"strings"
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

// EnsureUnderHome verifies cleanPath is contained within the home
// directory. Returns an error suitable for returning to the FTP client
// if the path escapes home. Comparison is case-insensitive on Windows
// (Windows file system is case-insensitive by default).
//
// This is the containment check WebFTP relies on to scope user access
// on Windows, where privilege demotion is a no-op and the alpamon
// process runs as the service account (typically SYSTEM). On Unix the
// demoted process's OS-level ACLs provide an equivalent protection.
//
// Callers should pass an absolute, cleaned home path and an absolute,
// cleaned target path. An empty home is treated as "no containment
// configured" and rejects everything to fail closed.
func EnsureUnderHome(home, cleanPath string) error {
	if home == "" {
		return fmt.Errorf("%s: no home directory configured", errPathEscapesHome)
	}
	root := filepath.Clean(home)
	target := cleanPath
	if runtime.GOOS == "windows" {
		root = strings.ToLower(root)
		target = strings.ToLower(target)
	}
	rel, err := filepath.Rel(root, target)
	if err != nil {
		return fmt.Errorf("%s: %w", errPathEscapesHome, err)
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return fmt.Errorf("%s", errPathEscapesHome)
	}
	return nil
}

const errPathEscapesHome = "path escapes home directory"
