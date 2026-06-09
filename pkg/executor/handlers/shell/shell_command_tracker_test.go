package shell

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/alpacax/alpamon/v2/internal/runnertest"
	"github.com/alpacax/alpamon/v2/pkg/executor/handlers/common"
	"github.com/alpacax/alpamon/v2/pkg/runner"
)

// hookRecordingExecutor wraps a MockCommandExecutor and records whether
// ExecWithStreamingHook (the shell handler's sole entry point into the
// executor) received a non-nil pidHook.
type hookRecordingExecutor struct {
	*common.MockCommandExecutor
	mu       sync.Mutex
	called   bool
	hookSeen bool
}

func (r *hookRecordingExecutor) ExecWithStreamingHook(
	ctx context.Context,
	args []string,
	username, groupname string,
	env map[string]string,
	timeout time.Duration,
	pidHook func(pid int),
	chunkCallback func(content string),
) (int, string, error) {
	r.mu.Lock()
	r.called = true
	r.hookSeen = pidHook != nil
	r.mu.Unlock()

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
		t.Error("ExecWithStreamingHook was not invoked")
	}
	if !rec.hookSeen {
		t.Error("shell handler must pass a non-nil hook when CommandID is set")
	}
	if _, ok := am.LookupPID(424242); ok {
		t.Error("tracker entry should have been removed after execution")
	}
}

// TestShellHandler_NoCommandID_PassesNilHook verifies that shell invocations
// without CommandID do not install a PID hook (so the PAM tracker is bypassed).
func TestShellHandler_NoCommandID_PassesNilHook(t *testing.T) {
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
	if !rec.called {
		t.Error("ExecWithStreamingHook should still be the entry point")
	}
	if rec.hookSeen {
		t.Error("shell handler must pass a nil hook when CommandID is empty")
	}
}
