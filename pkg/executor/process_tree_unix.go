//go:build !windows

package executor

import (
	"errors"
	"os"
	"os/exec"
	"sync"
	"syscall"
)

// commandCleanup mirrors the type in process_tree_windows.go; the commandCleaner assertion below pins
// the shared afterStart/cancel/close method set across build tags. State differs per platform.
type commandCleanup struct {
	mu       sync.Mutex // afterStart (main goroutine) writes pgid while cmd.Cancel's context watcher reads it
	pgid     int        // process group to SIGKILL; 0 when the child does not lead its own group
	canceled bool       // a cancel already fired; afterStart re-runs it once the group is recorded
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
	pgid := 0
	if p, err := syscall.Getpgid(cmd.Process.Pid); err == nil && p == cmd.Process.Pid {
		pgid = p
	}
	// A cancel that fired between Start and here read pgid==0 and hit only the leader; redo it with the group recorded.
	if canceled := c.recordPgid(pgid); canceled {
		return c.cancel(cmd)
	}
	return nil
}

func (c *commandCleanup) recordPgid(pgid int) (canceled bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pgid = pgid
	return c.canceled
}

func (c *commandCleanup) cancel(cmd *exec.Cmd) error {
	if cmd.Process == nil {
		return os.ErrProcessDone
	}
	pid := cmd.Process.Pid
	if pgid := c.markCanceled(); pgid != 0 {
		pid = -pgid
	}
	if err := syscall.Kill(pid, syscall.SIGKILL); err != nil {
		if errors.Is(err, syscall.ESRCH) {
			return os.ErrProcessDone
		}
		return err
	}
	return nil
}

// markCanceled records that a cancel fired and returns the recorded group; afterStart uses the flag to
// redo a kill that raced ahead of the group being recorded.
func (c *commandCleanup) markCanceled() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.canceled = true
	return c.pgid
}

func (c *commandCleanup) close() error {
	return nil
}
