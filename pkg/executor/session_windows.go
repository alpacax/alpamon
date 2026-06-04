//go:build windows

package executor

import "os/exec"

// enableSessionLeader is a no-op on Windows, which has no PAM/sudo session model.
func enableSessionLeader(cmd *exec.Cmd) {}
