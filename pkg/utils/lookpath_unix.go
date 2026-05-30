//go:build !windows

package utils

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// LookPath searches for an executable named file in the directories listed in
// pathEnv (a PATH-style, OS-list-separated string). If file already contains a
// path separator it is returned unchanged. It mirrors exec.LookPath but uses
// the supplied PATH instead of the current process environment, so command
// lookup can match the environment handed to a child process.
func LookPath(file, pathEnv string) (string, error) {
	if strings.ContainsRune(file, os.PathSeparator) {
		return file, nil
	}
	for _, dir := range filepath.SplitList(pathEnv) {
		// Skip empty PATH entries instead of resolving them against the
		// current directory. Alpamon runs as root, so honoring "." would
		// allow a cwd-relative binary to be picked up; the standard
		// exec.LookPath flags this case (ErrDot) for the same reason.
		if dir == "" {
			continue
		}
		path := filepath.Join(dir, file)
		if isExecutable(path) {
			return path, nil
		}
	}
	return "", &exec.Error{Name: file, Err: exec.ErrNotFound}
}

// isExecutable reports whether path is a regular file with at least one execute
// bit set.
func isExecutable(path string) bool {
	// codeql[go/path-injection]: Intentional - path is a command name supplied by
	// the trusted Alpacon console (same accepted flow as the exec.CommandContext
	// command lookup) and is only searched within a fixed set of trusted PATH
	// directories; this never executes the file, it only stats it.
	info, err := os.Stat(path) // lgtm[go/path-injection]
	if err != nil || info.IsDir() {
		return false
	}
	return info.Mode().Perm()&0o111 != 0
}
