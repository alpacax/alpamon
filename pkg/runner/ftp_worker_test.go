package runner

import (
	"os/exec"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func resetFtpWorkers(t *testing.T) {
	t.Helper()
	activeFtpWorkersMu.Lock()
	activeFtpWorkers = make(map[string]*ftpWorker)
	activeFtpWorkersMu.Unlock()
}

func ftpWorkerCount() int {
	activeFtpWorkersMu.Lock()
	defer activeFtpWorkersMu.Unlock()
	return len(activeFtpWorkers)
}

func TestRegisterUnregisterFtpWorker(t *testing.T) {
	resetFtpWorkers(t)

	cmdA := &exec.Cmd{}
	cmdB := &exec.Cmd{}
	_ = RegisterFtpWorker("s1", cmdA)

	require.Equal(t, 1, ftpWorkerCount(), "expected 1 worker after register")

	// Unregister with a different command must not drop the live entry.
	UnregisterFtpWorker("s1", cmdB)
	require.Equal(t, 1, ftpWorkerCount(), "expected worker to remain after mismatched unregister")

	// Unregister with the matching command removes it.
	UnregisterFtpWorker("s1", cmdA)
	require.Equal(t, 0, ftpWorkerCount(), "expected 0 workers after matching unregister")
}

func TestCloseAllActiveFtpWorkersSafeWhenEmptyOrNil(t *testing.T) {
	resetFtpWorkers(t)
	CloseAllActiveFtpWorkers() // empty map, must not panic

	// A worker with a nil command or an unstarted process must be a no-op,
	// never a nil-pointer panic.
	activeFtpWorkersMu.Lock()
	activeFtpWorkers["nilcmd"] = &ftpWorker{sessionID: "nilcmd", done: make(chan struct{})}
	activeFtpWorkers["nilproc"] = &ftpWorker{sessionID: "nilproc", cmd: &exec.Cmd{}, done: make(chan struct{})}
	activeFtpWorkersMu.Unlock()

	CloseAllActiveFtpWorkers()
	require.Equal(t, 0, ftpWorkerCount(), "expected registry cleared")
}

func TestCloseAllActiveFtpWorkersKillsWorker(t *testing.T) {
	if _, err := exec.LookPath("sleep"); err != nil {
		t.Skip("sleep not available on this platform")
	}
	resetFtpWorkers(t)

	cmd := exec.Command("sleep", "30")
	require.NoError(t, cmd.Start(), "failed to start worker process")

	// Mirror handleOpenFTP: the spawner owns the single Wait call and closes
	// done when the worker exits on its own.
	done := RegisterFtpWorker("s1", cmd)
	waited := make(chan struct{})
	go func() {
		_ = cmd.Wait()
		close(done)
		UnregisterFtpWorker("s1", cmd)
		close(waited)
	}()

	CloseAllActiveFtpWorkers()

	select {
	case <-waited:
	case <-time.After(5 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatal("worker did not exit after CloseAllActiveFtpWorkers")
	}

	require.Equal(t, 0, ftpWorkerCount(), "expected registry cleared after CloseAll")
}

func TestRegisterFtpWorkerStopsStaleOnSameSession(t *testing.T) {
	if _, err := exec.LookPath("sleep"); err != nil {
		t.Skip("sleep not available on this platform")
	}
	resetFtpWorkers(t)

	// First worker registered for the session.
	cmdA := exec.Command("sleep", "30")
	require.NoError(t, cmdA.Start(), "failed to start worker A")
	doneA := RegisterFtpWorker("s1", cmdA)
	stoppedA := make(chan struct{})
	go func() {
		_ = cmdA.Wait()
		close(doneA)
		UnregisterFtpWorker("s1", cmdA)
		close(stoppedA)
	}()

	// Re-registering the same session ID must stop the stale worker, not leak it.
	cmdB := exec.Command("sleep", "30")
	require.NoError(t, cmdB.Start(), "failed to start worker B")
	doneB := RegisterFtpWorker("s1", cmdB)
	stoppedB := make(chan struct{})
	go func() {
		_ = cmdB.Wait()
		close(doneB)
		UnregisterFtpWorker("s1", cmdB)
		close(stoppedB)
	}()

	select {
	case <-stoppedA:
	case <-time.After(5 * time.Second):
		_ = cmdA.Process.Kill()
		_ = cmdB.Process.Kill()
		t.Fatal("stale worker A was not stopped after same-session re-register")
	}

	require.Equal(t, 1, ftpWorkerCount(), "expected exactly 1 tracked worker after replace")

	CloseAllActiveFtpWorkers()
	select {
	case <-stoppedB:
	case <-time.After(5 * time.Second):
		_ = cmdB.Process.Kill()
		t.Fatal("worker B was not stopped after CloseAllActiveFtpWorkers")
	}
}
