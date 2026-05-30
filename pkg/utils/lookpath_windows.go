//go:build windows

package utils

import "os/exec"

// LookPath on Windows defers to the default exec resolution by returning
// ErrNotFound, signalling the caller to keep exec.Command's own lookup.
// Windows command resolution involves PATHEXT and other rules best left to the
// standard library; privilege demotion is also a no-op on Windows and
// DefaultPath mirrors the process PATH, so the child environment already
// matches the lookup environment.
func LookPath(file, pathEnv string) (string, error) {
	return "", exec.ErrNotFound
}
