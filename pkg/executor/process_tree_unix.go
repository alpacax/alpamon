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
	mu         sync.Mutex // afterStart (main goroutine) writes pgid while cmd.Cancel's context watcher reads it
	leadsGroup bool       // configure requested setsid/setpgid(0,0), so PGID == PID by construction
	pgid       int        // process group to SIGKILL; 0 when the child does not lead its own group
	canceled   bool       // a cancel already fired; afterStart re-runs it once the group is recorded
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

	sysAttr := cmd.SysProcAttr
	return &commandCleanup{leadsGroup: sysAttr.Setsid || (sysAttr.Setpgid && sysAttr.Pgid == 0)}, nil
}

// afterStart records the process group cancel should target: -pgid stays killable while a descendant holds
// the group open even after Wait reaps the leader (the post-reap leak path). Recorded only when the child
// leads its own group (PGID == PID), so -pgid can't hit an unrelated group.
func (c *commandCleanup) afterStart(cmd *exec.Cmd) error {
	if cmd.Process == nil {
		return os.ErrProcessDone
	}
	pgid := 0
	if c.leadsGroup {
		// Don't ask getpgid: on darwin it returns ESRCH for a signalled-but-unreaped leader, which would
		// drop the group in exactly the raced cancel handled below.
		pgid = cmd.Process.Pid
	} else if p, err := syscall.Getpgid(cmd.Process.Pid); err == nil && p == cmd.Process.Pid {
		pgid = p
	}
	// A cancel that fired between Start and here read pgid==0 and hit only the leader; redo it with the
	// group recorded. An already-gone group (ErrProcessDone) is the expected benign outcome, so let the
	// normal Wait path report the real termination status rather than surfacing it as an afterStart failure.
	if canceled := c.recordPgid(pgid); canceled {
		if err := c.cancel(cmd); err != nil && !errors.Is(err, os.ErrProcessDone) {
			return err
		}
	}
	return nil
}

func (c *commandCleanup) cancel(cmd *exec.Cmd) error {
	if cmd.Process == nil {
		return os.ErrProcessDone
	}
	pid := cmd.Process.Pid
	if pgid := c.takeForCancel(); pgid != 0 {
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

func (c *commandCleanup) close() error {
	return nil
}

// recordPgid stores the group cancel should target and reports whether a cancel already fired, which is
// what tells afterStart to redo the kill.
func (c *commandCleanup) recordPgid(pgid int) (canceled bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pgid = pgid
	return c.canceled
}

// Mirrors the Windows sibling: records that a cancel fired and hands back the group, so cancel's SIGKILL
// runs lock-free. afterStart uses the flag to redo a kill that raced ahead of the group being recorded.
func (c *commandCleanup) takeForCancel() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.canceled = true
	return c.pgid
}
