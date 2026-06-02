//go:build windows

package utils

import "os/exec"

// ApplyCommandPath is a no-op on Windows: command resolution involves PATHEXT
// and other rules best left to the standard library, privilege demotion is a
// no-op, and DefaultPath mirrors the process PATH, so exec.Command's own lookup
// already matches the child environment.
func ApplyCommandPath(cmd *exec.Cmd, file, pathEnv string) {}
