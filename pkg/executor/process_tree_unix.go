//go:build !windows

package executor

import (
	"errors"
	"os"
	"os/exec"
	"syscall"
)

// commandCleanup mirrors the type in process_tree_windows.go; runCommand (executor.go) consumes
// the same afterStart/cancel/close method set, unenforced across build tags, so keep the two in sync.
type commandCleanup struct{}

func configureProcessTreeCleanup(cmd *exec.Cmd, sessionLeader bool) (commandCleanup, error) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}

	if sessionLeader {
		// PID-hooked commands stay session leaders for PAM/sudo lookup; setsid already gives PGID == PID for group kill.
		// Setpgid must stay false: setpgid on a setsid session leader is EPERM, which would fail cmd.Start().
		cmd.SysProcAttr.Setsid = true
		cmd.SysProcAttr.Setpgid = false
	} else if !cmd.SysProcAttr.Setsid {
		cmd.SysProcAttr.Setpgid = true
	}

	return commandCleanup{}, nil
}

func (commandCleanup) afterStart(_ *exec.Cmd) error {
	return nil
}

func (commandCleanup) cancel(cmd *exec.Cmd) error {
	if cmd.Process == nil {
		return os.ErrProcessDone
	}
	pid := cmd.Process.Pid
	// Group-kill only when the child leads its own group (PGID == PID); else -pid could hit an unrelated group.
	if pgid, err := syscall.Getpgid(pid); err == nil && pgid == pid {
		pid = -pid
	}
	if err := syscall.Kill(pid, syscall.SIGKILL); err != nil {
		if errors.Is(err, syscall.ESRCH) {
			return os.ErrProcessDone
		}
		return err
	}
	return nil
}

func (commandCleanup) close() error {
	return nil
}
