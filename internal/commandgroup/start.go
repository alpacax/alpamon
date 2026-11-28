package commandgroup

import (
	"context"
	"os/exec"
)

type startKey struct{}

// WithStartHook installs a hook that opens the PID publication window and
// returns a function to close it, including on a failed start.
func WithStartHook(ctx context.Context, begin func(uid string) func()) context.Context {
	return context.WithValue(ctx, startKey{}, begin)
}

func BeginStart(ctx context.Context, cmd *exec.Cmd) func() {
	if begin, ok := ctx.Value(startKey{}).(func(string) func()); ok {
		return begin(startUID(cmd))
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
