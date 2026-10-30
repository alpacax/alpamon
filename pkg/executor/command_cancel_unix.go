//go:build !windows

package executor

import (
	"os/exec"
	"time"

	"github.com/alpacax/alpamon/v2/internal/commandcancel"
)

func (c *commandCleanup) cancelRemote(cmd *exec.Cmd, grace time.Duration) (cleanupOutcome, error) {
	if !c.leadsGroup {
		return c.cancel(cmd)
	}
	terminate := commandcancel.TerminateGroup
	if cmd.SysProcAttr != nil && cmd.SysProcAttr.Setsid {
		terminate = commandcancel.TerminateSession
	}
	survivors, signalled, err := terminate(cmd.Process.Pid, grace)
	return cleanupOutcome{assigned: true, rootKilled: signalled, survivors: survivors}, err
}

func watchCommandExit(cmd *exec.Cmd, _ *commandCleanup) (<-chan error, error) {
	done := make(chan error, 1)
	go func() { done <- commandcancel.WaitExited(cmd.Process.Pid) }()
	return done, nil
}
