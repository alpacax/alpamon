package commandgroup

import (
	"context"
	"os/exec"
	"sync"
)

type lockKey struct{}

// WithStartLock coordinates PID publication with authorization on platforms
// where the process hierarchy is the only available session identifier.
func WithStartLock(ctx context.Context, lock *sync.RWMutex) context.Context {
	return context.WithValue(ctx, lockKey{}, lock)
}

func LockStart(ctx context.Context) func() {
	if lock, ok := ctx.Value(lockKey{}).(*sync.RWMutex); ok {
		lock.Lock()
		return lock.Unlock
	}
	return func() {}
}

// A failed Start consumes exec.Cmd. A kernel without clone-into-cgroup
// support can still launch under the synchronized PID and ancestor tracker.
func StartCommand(ctx context.Context, cmd *exec.Cmd, start func(*exec.Cmd) error) (*exec.Cmd, error) {
	err := start(cmd)
	if !Unsupported(cmd, err) {
		return cmd, err
	}
	retry := exec.CommandContext(ctx, cmd.Path)
	retry.Path, retry.Args, retry.Dir, retry.Env = cmd.Path, cmd.Args, cmd.Dir, cmd.Env
	retry.Stdin, retry.Stdout, retry.Stderr = cmd.Stdin, cmd.Stdout, cmd.Stderr
	retry.ExtraFiles, retry.SysProcAttr = cmd.ExtraFiles, cmd.SysProcAttr
	retry.Cancel = nil
	return retry, start(retry)
}
