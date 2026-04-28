package shell

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/alpacax/alpamon/pkg/executor/handlers/common"
	"github.com/alpacax/alpamon/pkg/runner"
	"github.com/alpacax/alpamon/internal/runnertest"
)

// hookRecordingExecutor wraps a MockCommandExecutor and records whether
// ExecWithHook was invoked and whether it passed through a non-nil hook.
// It is deliberately local to the shell handler tests so it cannot be
// accidentally reused by other handlers and mask real breakage.
type hookRecordingExecutor struct {
	*common.MockCommandExecutor
	mu       sync.Mutex
	called   bool
	hookSeen bool
}

func (r *hookRecordingExecutor) ExecWithHook(
	ctx context.Context,
	args []string,
	username, groupname string,
	env map[string]string,
	timeout time.Duration,
	pidHook func(pid int),
) (int, string, error) {
	r.mu.Lock()
	r.called = true
	r.hookSeen = pidHook != nil
	r.mu.Unlock()

	// Simulate the executor's post-fork callback so the shell handler
	// exercises the Register/Unregister lifecycle.
	if pidHook != nil {
		pidHook(424242)
	}
	return r.Exec(ctx, args, username, groupname, env, timeout)
}

// withTrackerAuthManager installs a clean in-process AuthManager for the
// duration of t and restores the previous singleton on cleanup.
func withTrackerAuthManager(t *testing.T) *runner.AuthManager {
	t.Helper()
	return runnertest.SwapAuthManager(t, runnertest.NewAuthManager())
}

// TestShellHandler_CommandID_RegistersAndUnregistersPID verifies that a
// shell invocation carrying CommandID uses the hook path and cleans up
// the tracker entry after execution.
func TestShellHandler_CommandID_RegistersAndUnregistersPID(t *testing.T) {
	am := withTrackerAuthManager(t)

	mock := common.NewMockCommandExecutor(t)
	rec := &hookRecordingExecutor{MockCommandExecutor: mock}

	handler := NewShellHandler(rec)
	args := &common.CommandArgs{
		CommandID: "cmd-xyz",
		Command:   "echo hello",
		Username:  "alice",
		AllowSh:   true,
	}

	exit, _, err := handler.Execute(context.Background(), common.ShellCmd.String(), args)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if exit != 0 {
		t.Errorf("exit: got %d, want 0", exit)
	}
	if !rec.called {
		t.Error("ExecWithHook was not invoked")
	}
	if !rec.hookSeen {
		t.Error("shell handler must pass a non-nil hook when CommandID is set")
	}
	if _, ok := am.LookupPID(424242); ok {
		t.Error("tracker entry should have been removed after execution")
	}
}

// TestShellHandler_NoCommandID_UsesPlainExec verifies that internal /
// non-Command shell invocations keep the original, hook-less code path
// so we don't accidentally regress performance or behaviour.
func TestShellHandler_NoCommandID_UsesPlainExec(t *testing.T) {
	_ = withTrackerAuthManager(t)

	mock := common.NewMockCommandExecutor(t)
	rec := &hookRecordingExecutor{MockCommandExecutor: mock}

	handler := NewShellHandler(rec)
	args := &common.CommandArgs{
		Command:  "echo ok",
		Username: "alice",
		AllowSh:  true,
	}

	if _, _, err := handler.Execute(context.Background(), common.ShellCmd.String(), args); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rec.called {
		t.Error("ExecWithHook should not be used when CommandID is empty")
	}
}
