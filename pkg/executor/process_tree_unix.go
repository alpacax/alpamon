//go:build !windows

package executor

import (
	"errors"
	"os"
	"os/exec"
	"syscall"
)

// commandCleanup mirrors the type in process_tree_windows.go; the commandCleaner assertion below pins
// the shared afterStart/cancel/close method set across build tags. State differs per platform.
type commandCleanup struct {
	pgid int // process group to SIGKILL; 0 when the child does not lead its own group
}

var _ commandCleaner = (*commandCleanup)(nil)

func configureProcessTreeCleanup(cmd *exec.Cmd, sessionLeader bool) (*commandCleanup, error) {
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

	return &commandCleanup{}, nil
}

// afterStart captures the process group while the leader is alive: getpgid fails with ESRCH once Wait
// reaps it, yet -pgid stays killable while a descendant holds the group open (the post-reap leak path).
// Recorded only when the child leads its own group (PGID == PID), so -pgid can't hit an unrelated group.
func (c *commandCleanup) afterStart(cmd *exec.Cmd) error {
	if cmd.Process == nil {
		return os.ErrProcessDone
	}
	if pgid, err := syscall.Getpgid(cmd.Process.Pid); err == nil && pgid == cmd.Process.Pid {
		c.pgid = pgid
	}
	return nil
}

func (c *commandCleanup) cancel(cmd *exec.Cmd) error {
	if cmd.Process == nil {
		return os.ErrProcessDone
	}
	pid := cmd.Process.Pid
	if c.pgid != 0 {
		pid = -c.pgid
	}
	if err := syscall.Kill(pid, syscall.SIGKILL); err != nil {
		if errors.Is(err, syscall.ESRCH) {
			return os.ErrProcessDone
		}
		return err
	}
	return nil
}

func (c *commandCleanup) close() error {
	return nil
}
