//go:build !windows

package runner

import (
	"fmt"
	"net"
	"path/filepath"
	"syscall"
	"time"

	"github.com/rs/zerolog/log"
)

// startTunnelRelay spawns the per-session tunnel daemon (demoted to nobody on
// Linux, current user on macOS), which relays every stream over UDS.
// daemonMu serializes it against stopTunnelRelay: a concurrent closetunnel
// either waits for the spawn and then kills it, or wins the lock first and
// the closed context stops the spawn from happening at all.
func (tc *TunnelClient) startTunnelRelay() error {
	tc.daemonMu.Lock()
	defer tc.daemonMu.Unlock()

	if err := tc.ctx.Err(); err != nil {
		return fmt.Errorf("tunnel session closed before relay start: %w", err)
	}

	if !IsValidSessionID(tc.sessionID) {
		return fmt.Errorf("invalid session ID for tunnel daemon socket")
	}

	socketDir, err := ensureTunnelSocketDir()
	if err != nil {
		return fmt.Errorf("failed to ensure tunnel socket directory: %w", err)
	}
	tc.daemonSocket = filepath.Join(socketDir, tc.sessionID+".sock")

	cmd, err := spawnTunnelDaemon(tc.daemonSocket)
	if err != nil {
		return fmt.Errorf("failed to spawn tunnel daemon: %w", err)
	}
	tc.daemonCmd = cmd

	if err := tc.waitForDaemonReady(); err != nil {
		// Daemon failed to start, clean up
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		_ = safeRemoveSocket(tc.daemonSocket)
		return fmt.Errorf("tunnel daemon not ready: %w", err)
	}

	log.Info().Msgf("Tunnel daemon ready for session %s, socket: %s.", tc.sessionID, tc.daemonSocket)
	return nil
}

// waitForDaemonReady polls the UDS socket until the daemon is accepting connections.
func (tc *TunnelClient) waitForDaemonReady() error {
	deadline := time.Now().Add(5 * time.Second)

	for time.Now().Before(deadline) {
		conn, err := net.Dial("unix", tc.daemonSocket)
		if err == nil {
			_ = conn.Close()
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}

	return fmt.Errorf("timeout waiting for daemon socket %s", tc.daemonSocket)
}

// dialTunnelTarget connects to the tunnel daemon via UDS and sends the target address.
func (tc *TunnelClient) dialTunnelTarget(targetAddr string) (net.Conn, error) {
	conn, err := net.Dial("unix", tc.daemonSocket)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to daemon socket: %w", err)
	}

	if _, err := fmt.Fprintf(conn, "%s\n", targetAddr); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("failed to send target address to daemon: %w", err)
	}

	return conn, nil
}

func (tc *TunnelClient) stopTunnelRelay() {
	tc.daemonMu.Lock()
	defer tc.daemonMu.Unlock()

	// Local copy so the Wait goroutine below cannot observe the nil
	// assignment at the end of this function.
	cmd := tc.daemonCmd
	if cmd == nil || cmd.Process == nil {
		return
	}

	log.Info().Msgf("Stopping tunnel daemon for session %s...", tc.sessionID)

	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		log.Debug().Err(err).Msg("SIGTERM failed for tunnel daemon, trying SIGKILL.")
		_ = cmd.Process.Kill()
	}

	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()

	select {
	case <-done:
		log.Info().Msg("Tunnel daemon stopped.")
	case <-time.After(10 * time.Second):
		_ = cmd.Process.Kill()
		log.Warn().Msg("Tunnel daemon killed after timeout.")
	}

	_ = safeRemoveSocket(tc.daemonSocket)
	tc.daemonCmd = nil
}
