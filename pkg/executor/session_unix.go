//go:build !windows

package executor

import (
	"os/exec"
	"syscall"
)

// enableSessionLeader makes cmd start in a new session (setsid) so its pid
// becomes the session-leader pid that the PAM tracker registers. sudo invoked
// inside the command then resolves back to the originating Command by session
// ID—including when the shell execs sudo and they share a pid. The new session
// has no controlling terminal, which is correct for non-interactive command
// execution. It is merged into any existing SysProcAttr (e.g. privilege
// demotion) rather than replacing it.
func enableSessionLeader(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Setsid = true
}
