//go:build !windows

package runner

import (
	"bufio"
	"context"
	"os"
	"os/exec"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newManagerWithProcess puts the child in its own process group, so
// terminateProcess signals it and not the test binary.
func newManagerWithProcess(t *testing.T) (*CodeServerManager, *exec.Cmd) {
	t.Helper()

	ctx, cancel := context.WithCancel(t.Context())

	cmd := exec.CommandContext(ctx, "sleep", "300")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	require.NoError(t, cmd.Start())
	t.Cleanup(func() {
		_ = terminateProcess(cmd.Process)
	})

	m := &CodeServerManager{
		cmd:    cmd,
		ctx:    ctx,
		cancel: cancel,
		status: CodeServerStatusStarting,
	}
	return m, cmd
}

// TestStopBeforeStarted covers doStart's waitForReady failure path: it calls
// Stop before m.started is set—gating teardown on that flag leaks the process.
func TestStopBeforeStarted(t *testing.T) {
	m, cmd := newManagerWithProcess(t)

	require.NoError(t, m.Stop())

	require.NotNil(t, cmd.ProcessState, "Stop must terminate and reap the process")
	ws, ok := cmd.ProcessState.Sys().(syscall.WaitStatus)
	require.True(t, ok)
	require.True(t, ws.Signaled(), "the process should have died from a signal, not exited on its own")
	assert.Equal(t, syscall.SIGTERM, ws.Signal(), "Stop should terminate gracefully before falling back to SIGKILL")
	assert.ErrorIs(t, m.ctx.Err(), context.Canceled, "Stop must cancel the manager context")
}

// TestStopTwice mirrors tunnel_client stopping a manager that doStart already
// stopped on its failure path.
func TestStopTwice(t *testing.T) {
	m, _ := newManagerWithProcess(t)

	require.NoError(t, m.Stop())
	require.NoError(t, m.Stop(), "the second Stop must be a no-op, not another signal at a reaped pid")
	assert.Nil(t, m.cmd, "Stop must clear m.cmd so a later Stop has nothing to signal")
}

// TestStopWithoutProcess covers Stop during the install phase, which must abort
// installCodeServer through the context.
func TestStopWithoutProcess(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())

	m := &CodeServerManager{ctx: ctx, cancel: cancel, status: CodeServerStatusInstalling}

	require.NoError(t, m.Stop())
	assert.ErrorIs(t, ctx.Err(), context.Canceled, "Stop must cancel the context even with no process to signal")
}

func TestStopClearsRunningState(t *testing.T) {
	m, _ := newManagerWithProcess(t)
	m.started = true

	require.NoError(t, m.Stop())
	assert.False(t, m.IsRunning(), "Stop must clear m.started")
}

// TestStopKeepsStatusAnswerable pins Stop inside its wait with a child that
// ignores SIGTERM and reports it, so no sleep or deadline is needed.
func TestStopKeepsStatusAnswerable(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())

	cmd := exec.CommandContext(ctx, "sh", "-c", `trap 'echo signalled' TERM; echo ready; while :; do sleep 1; done`)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	// os.Pipe, not cmd.StdoutPipe: the read end stays ours, so reading does not
	// race the cmd.Wait() Stop runs concurrently.
	pr, pw, err := os.Pipe()
	require.NoError(t, err)
	cmd.Stdout = pw
	t.Cleanup(func() { _ = pr.Close() })

	require.NoError(t, cmd.Start())
	require.NoError(t, pw.Close())
	t.Cleanup(func() {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	})

	m := &CodeServerManager{
		cmd:    cmd,
		ctx:    ctx,
		cancel: cancel,
		status: CodeServerStatusStarting,
	}

	// The child announces itself once the trap is installed: an earlier SIGTERM
	// would kill it by default and the read below would see EOF.
	child := bufio.NewReader(pr)
	line, err := child.ReadString('\n')
	require.NoError(t, err)
	require.Equal(t, "ready\n", line)

	stopped := make(chan error, 1)
	go func() {
		stopped <- m.Stop()
	}()

	line, err = child.ReadString('\n')
	require.NoError(t, err)
	require.Equal(t, "signalled\n", line, "the child should have reported the SIGTERM Stop sent")

	require.True(t, m.mu.TryRLock(), "Stop must release m.mu before waiting on the process")
	m.mu.RUnlock()

	status, _ := m.Status()
	assert.Equal(t, CodeServerStatusStarting, status)

	require.NoError(t, syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL))
	require.NoError(t, <-stopped)
}
