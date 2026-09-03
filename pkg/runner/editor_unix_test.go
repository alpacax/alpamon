//go:build !windows

package runner

import (
	"bufio"
	"context"
	"io"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// killGroupOnCleanup kills the child's group unless the reaper already closed
// done: a reaped pid is free for reuse, so the group may no longer be ours.
func killGroupOnCleanup(t *testing.T, cmd *exec.Cmd, done <-chan struct{}) {
	t.Helper()

	pgid := cmd.Process.Pid
	t.Cleanup(func() {
		select {
		case <-done:
			return
		default:
		}

		_ = syscall.Kill(-pgid, syscall.SIGKILL)
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Errorf("process group %d outlived the test", pgid)
		}
	})
}

// newManagerWithProcess puts the child in its own process group, so
// terminateProcess signals it and not the test binary.
func newManagerWithProcess(t *testing.T) (*CodeServerManager, *exec.Cmd) {
	t.Helper()

	ctx, cancel := context.WithCancel(t.Context())

	cmd := exec.CommandContext(ctx, "sleep", "300")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	require.NoError(t, cmd.Start())

	waitDone := reapProcess(cmd)
	killGroupOnCleanup(t, cmd, waitDone)

	m := &CodeServerManager{
		cmd:         cmd,
		waitDone:    waitDone,
		ctx:         ctx,
		cancel:      cancel,
		status:      CodeServerStatusStarting,
		stopGrace:   codeServerStopGrace,
		terminateFn: terminateProcess,
	}
	return m, cmd
}

// newManagerWithScript reads the "ready" line the script prints: a signal arriving
// before the script installs its trap would kill it by the default disposition.
func newManagerWithScript(t *testing.T, script string) (*CodeServerManager, *exec.Cmd, *bufio.Reader) {
	t.Helper()

	ctx, cancel := context.WithCancel(t.Context())

	cmd := exec.CommandContext(ctx, "sh", "-c", script)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	// os.Pipe, not cmd.StdoutPipe: the read end stays ours, so reading does not
	// race the cmd.Wait() the reaper runs concurrently.
	pr, pw, err := os.Pipe()
	require.NoError(t, err)
	cmd.Stdout = pw
	t.Cleanup(func() { _ = pr.Close() })

	require.NoError(t, cmd.Start())
	require.NoError(t, pw.Close())

	waitDone := reapProcess(cmd)
	killGroupOnCleanup(t, cmd, waitDone)

	child := bufio.NewReader(pr)
	line, err := child.ReadString('\n')
	require.NoError(t, err)
	require.Equal(t, "ready\n", line)

	m := &CodeServerManager{
		cmd:         cmd,
		waitDone:    waitDone,
		ctx:         ctx,
		cancel:      cancel,
		status:      CodeServerStatusStarting,
		stopGrace:   codeServerStopGrace,
		terminateFn: terminateProcess,
	}
	return m, cmd, child
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
	m, cmd, child := newManagerWithScript(t,
		`trap 'echo signalled' TERM; echo ready; while :; do sleep 1; done`)

	stopped := make(chan error, 1)
	go func() {
		stopped <- m.Stop()
	}()

	line, err := child.ReadString('\n')
	require.NoError(t, err)
	require.Equal(t, "signalled\n", line, "the child should have reported the SIGTERM Stop sent")

	require.True(t, m.mu.TryRLock(), "Stop must release m.mu before waiting on the process")
	m.mu.RUnlock()

	status, _ := m.Status()
	assert.Equal(t, CodeServerStatusStarting, status)

	require.NoError(t, syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL))
	require.NoError(t, <-stopped)
}

// TestStopWaitsAfterSignalFailure: a signal that does not land still leaves a child to collect.
func TestStopWaitsAfterSignalFailure(t *testing.T) {
	m, cmd := newManagerWithProcess(t)

	// Kills the child from inside the failing call, so the reap cannot land first.
	m.terminateFn = func(p *os.Process) error {
		_ = syscall.Kill(-p.Pid, syscall.SIGKILL)
		return syscall.ESRCH
	}

	require.NoError(t, m.Stop(), "a failed signal is not a failure to stop")
	require.NotNil(t, cmd.ProcessState, "Stop returned before the process was reaped")
}

// TestWaitForReadySurvivesConcurrentStop covers TunnelClient.Close mid-startup, where Stop clears m.cmd.
func TestWaitForReadySurvivesConcurrentStop(t *testing.T) {
	m, _ := newManagerWithProcess(t)

	// Nothing listens on it, so every dial fails and the loop keeps running.
	port, err := findAvailablePort()
	require.NoError(t, err)
	m.port = port

	// Read before Stop nils the field, not from inside the goroutine.
	waitDone := m.waitDone
	ready := make(chan error, 1)
	go func() {
		ready <- m.waitForReady(waitDone)
	}()

	require.NoError(t, m.Stop())
	assert.ErrorContains(t, <-ready, "exited unexpectedly")
}

// TestStopKillsGroupIgnoringSIGTERM: on timeout the whole group must die.
// exec.CommandContext's own kill reaches only the leader.
func TestStopKillsGroupIgnoringSIGTERM(t *testing.T) {
	// Both shells ignore SIGTERM, so only SIGKILL at the group ends them.
	m, _, child := newManagerWithScript(t,
		`trap '' TERM; sh -c "trap '' TERM; while :; do sleep 1; done" & echo ready; while :; do sleep 1; done`)
	m.stopGrace = 200 * time.Millisecond

	require.ErrorContains(t, m.Stop(), "did not exit within")

	// Both shells hold the write end, so EOF means both are gone. kill(-pgid, 0)
	// would not do: it still finds a zombie that a container init never reaps.
	drained := make(chan error, 1)
	go func() {
		_, err := io.ReadAll(child)
		drained <- err
	}()

	select {
	case err := <-drained:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("Stop gave up on the process group but left it running")
	}
}
