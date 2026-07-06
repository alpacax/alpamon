//go:build !windows

package executor

import (
	"errors"
	"os"
	"os/exec"
	"syscall"
)

type commandCleanup struct{}

func configureProcessTreeCleanup(cmd *exec.Cmd, sessionLeader bool) (commandCleanup, error) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}

	if sessionLeader {
		// PID-hooked commands stay session leaders for PAM/sudo lookup; setsid also gives PGID == PID for group kill.
		cmd.SysProcAttr.Setsid = true
		cmd.SysProcAttr.Setpgid = false
	} else if !cmd.SysProcAttr.Setsid {
		cmd.SysProcAttr.Setpgid = true
	}

	return commandCleanup{}, nil
}

func (commandCleanup) afterStart(cmd *exec.Cmd) error {
	return nil
}

func (commandCleanup) cancel(cmd *exec.Cmd) error {
	if cmd.Process == nil {
		return os.ErrProcessDone
	}
	if err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL); err != nil {
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
