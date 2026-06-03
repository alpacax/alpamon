package runner

import (
	"os/exec"
	"sync"
	"syscall"
	"time"

	"github.com/rs/zerolog/log"
)

// ftpWorkerStopTimeout bounds how long a worker is given to exit after SIGTERM
// before it is force-killed, mirroring the tunnel daemon stop behavior.
const ftpWorkerStopTimeout = 10 * time.Second

// ftpWorker tracks a spawned `alpamon ftp` worker process so it can be reaped
// on shutdown. done is closed by the spawner once the worker has exited on its
// own, letting stopFtpWorker wait for a graceful exit without racing the
// spawner on exec.Cmd.Wait (which must be called exactly once).
type ftpWorker struct {
	sessionID string
	cmd       *exec.Cmd
	done      chan struct{}
}

var (
	// activeFtpWorkers tracks running WebFTP worker processes by session ID.
	// Each WebFTP session spawns alpamon as an `alpamon ftp` child process;
	// without explicit cleanup these only died because systemd's default
	// KillMode=control-group tore down the whole cgroup. With KillMode=process
	// they must be reaped here so a restart does not orphan them.
	activeFtpWorkers   = make(map[string]*ftpWorker)
	activeFtpWorkersMu sync.Mutex
)

// RegisterFtpWorker records a started worker process and returns a channel the
// caller must close once the worker exits on its own. The caller still owns the
// single exec.Cmd.Wait call.
func RegisterFtpWorker(sessionID string, cmd *exec.Cmd) chan struct{} {
	done := make(chan struct{})
	worker := &ftpWorker{sessionID: sessionID, cmd: cmd, done: done}

	activeFtpWorkersMu.Lock()
	stale := activeFtpWorkers[sessionID]
	activeFtpWorkers[sessionID] = worker
	activeFtpWorkersMu.Unlock()

	// A live worker under the same session ID would otherwise be dropped from
	// the table and never reaped. Session IDs are unique per WebFTP session, so
	// this is not expected, but it must not silently leak a process if it happens.
	if stale != nil {
		log.Warn().Str("sessionID", sessionID).
			Msg("Replacing an already-tracked FTP worker; stopping the stale one.")
		go stopFtpWorker(stale)
	}

	return done
}

// UnregisterFtpWorker drops the worker for sessionID, but only if it still maps
// to the same command, so a worker that exits after a same-session worker has
// replaced it does not delete the newer entry.
func UnregisterFtpWorker(sessionID string, cmd *exec.Cmd) {
	activeFtpWorkersMu.Lock()
	if worker, ok := activeFtpWorkers[sessionID]; ok && worker.cmd == cmd {
		delete(activeFtpWorkers, sessionID)
	}
	activeFtpWorkersMu.Unlock()
}

// CloseAllActiveFtpWorkers terminates all tracked WebFTP worker processes.
// Called during graceful shutdown so the agent reaps its own helper processes
// instead of relying on the systemd cgroup kill.
func CloseAllActiveFtpWorkers() {
	activeFtpWorkersMu.Lock()
	workers := make([]*ftpWorker, 0, len(activeFtpWorkers))
	for _, worker := range activeFtpWorkers {
		workers = append(workers, worker)
	}
	activeFtpWorkers = make(map[string]*ftpWorker)
	activeFtpWorkersMu.Unlock()

	for _, worker := range workers {
		log.Info().Str("sessionID", worker.sessionID).Msg("Stopping FTP worker during shutdown.")
		stopFtpWorker(worker)
	}
}

// stopFtpWorker signals a single worker process to exit. It deliberately targets
// the process (not its process group): WebFTP workers are not started in their
// own group, so a negative-PID signal would hit Alpamon's own group. SIGTERM is
// tried first for a clean shutdown, falling back to a force kill (Process.Kill)
// on timeout, or immediately on platforms where SIGTERM is unsupported (Windows).
func stopFtpWorker(worker *ftpWorker) {
	if worker == nil || worker.cmd == nil || worker.cmd.Process == nil {
		return
	}

	if err := worker.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		log.Debug().Err(err).Str("sessionID", worker.sessionID).
			Msg("SIGTERM failed for FTP worker, killing.")
		_ = worker.cmd.Process.Kill()
		return
	}

	select {
	case <-worker.done:
	case <-time.After(ftpWorkerStopTimeout):
		log.Warn().Str("sessionID", worker.sessionID).
			Msg("FTP worker did not exit after SIGTERM, killing.")
		_ = worker.cmd.Process.Kill()
	}
}
