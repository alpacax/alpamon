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
		// Only resolve against absolute, trusted directories. Empty or
		// relative entries (".", "bin") would be stat'd relative to Alpamon's
		// current working directory, which may differ from the child's cmd.Dir
		// and reintroduces cwd-dependent lookup; the standard exec.LookPath
		// flags relative resolution (ErrDot) for the same reason. Alpamon also
		// runs as root, making a cwd-relative binary especially dangerous.
		if !filepath.IsAbs(dir) {
			continue
		}
		path := filepath.Join(dir, file)
		if isExecutable(path) {
			return path, nil
		}
	}
	return "", &exec.Error{Name: file, Err: exec.ErrNotFound}
}

// ApplyCommandPath pins cmd to the executable resolved against pathEnv. On Unix,
// a bare command name that is not found in pathEnv is recorded as a lookup
// failure on cmd.Err rather than being left to fall back to Alpamon's process
// PATH, so command lookup and execution share the same environment.
func ApplyCommandPath(cmd *exec.Cmd, file, pathEnv string) {
	resolved, err := LookPath(file, pathEnv)
	if err != nil {
		cmd.Path = file
		cmd.Err = err
		return
	}
	cmd.Path = resolved
	cmd.Err = nil
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
