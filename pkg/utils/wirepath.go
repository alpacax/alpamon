package utils

import (
	"errors"
	"fmt"
	"io/fs"
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
//
// This check is lexical only. To prevent symlink/junction escapes (a
// user creating a link inside home that points outside), callers must
// first resolve the target with ResolveSymlinksBestEffort and use the
// resolved path for containment.
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

// ResolveSymlinksBestEffort resolves all symlinks and junctions in
// cleanPath. If cleanPath does not exist yet (for example, when a user
// is about to create a new file), the nearest existing ancestor is
// resolved and the remaining trailing components are appended
// literally. This is needed so a symlink inside the home directory
// cannot be used to redirect subsequent file operations outside the
// home: see EnsureUnderHome.
//
// Errors other than "not exist" are returned as-is (permission denied,
// too many links, etc.) so callers can distinguish a missing leaf
// from a real failure.
//
// Note: this check is still subject to TOCTOU races. A user who can
// create symlinks inside their home could swap a resolved component
// between the check and the underlying os call. Closing that hole
// requires atomic O_NOFOLLOW semantics which Go does not expose
// portably on Windows.
func ResolveSymlinksBestEffort(cleanPath string) (string, error) {
	if cleanPath == "" {
		return "", fmt.Errorf("empty path")
	}
	resolved, err := filepath.EvalSymlinks(cleanPath)
	if err == nil {
		return resolved, nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return "", err
	}
	parent, tail := filepath.Split(cleanPath)
	// Preserve a volume or filesystem root separator instead of
	// trimming it away. On Windows `C:\\` must stay `C:\\`; trimming
	// to `C:` would turn an absolute path drive-relative and change
	// path semantics for later os calls.
	parent = trimTrailingSeparatorPreservingRoot(parent)
	if parent == "" || parent == cleanPath {
		return cleanPath, nil
	}
	resolvedParent, err := ResolveSymlinksBestEffort(parent)
	if err != nil {
		return "", err
	}
	return filepath.Join(resolvedParent, tail), nil
}

// trimTrailingSeparatorPreservingRoot strips a single trailing path
// separator unless doing so would leave only a volume or filesystem
// root. Examples:
//
//	"/foo/"    -> "/foo"
//	"/"        -> "/"          (preserved)
//	"C:\\foo\\" -> "C:\\foo"
//	"C:\\"      -> "C:\\"       (preserved)
//	"\\\\srv\\share\\" -> "\\\\srv\\share" (UNC share root)
func trimTrailingSeparatorPreservingRoot(p string) string {
	if p == "" {
		return p
	}
	// filepath.VolumeName handles both drive letters (C:) and UNC
	// prefixes (\\server\share) on Windows, and returns "" on Unix.
	vol := filepath.VolumeName(p)
	trimmed := strings.TrimRight(p, string(filepath.Separator))
	// If trimming would leave us at or below the volume root, return
	// the root form instead of the drive-relative form.
	if trimmed == vol {
		return vol + string(filepath.Separator)
	}
	if trimmed == "" {
		// Unix "/" case.
		return string(filepath.Separator)
	}
	return trimmed
}

// ResolveAndEnsureUnderHome resolves symlinks/junctions on both home
// and target, then verifies the resolved target is contained within
// the resolved home. Returns the resolved target path on success.
// An empty home short-circuits with the EnsureUnderHome message so
// callers get a clear, actionable error; the alternative, passing ""
// to ResolveSymlinksBestEffort, emits a generic "empty path" error.
func ResolveAndEnsureUnderHome(home, target string) (string, error) {
	if home == "" {
		return "", fmt.Errorf("%s: no home directory configured", errPathEscapesHome)
	}
	resolvedHome, err := ResolveSymlinksBestEffort(home)
	if err != nil {
		return "", err
	}
	resolvedTarget, err := ResolveSymlinksBestEffort(target)
	if err != nil {
		return "", err
	}
	if err := EnsureUnderHome(resolvedHome, resolvedTarget); err != nil {
		return "", err
	}
	return resolvedTarget, nil
}
