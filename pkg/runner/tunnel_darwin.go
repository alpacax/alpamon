//go:build darwin

package runner

import (
	"fmt"
	"io"
	"os"
	"os/exec"

	"github.com/rs/zerolog/log"
)

// spawnTunnelWorker spawns a tunnel worker subprocess.
// On macOS, credential demotion is not supported, so the subprocess runs as the current user.
func spawnTunnelWorker(username, groupname, targetAddr string) (*exec.Cmd, io.WriteCloser, io.ReadCloser, error) {
	// macOS does not support syscall.Credential in SysProcAttr
	log.Warn().
		Str("username", username).
		Str("groupname", groupname).
		Msg("Credential demotion not supported on macOS. Running tunnel worker as current user.")

	// Get current executable path
	executable, err := os.Executable()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to get executable path: %w", err)
	}

	// Create command for tunnel worker subprocess (without credential demotion)
	cmd := exec.Command(executable, "tunnel-worker", targetAddr)
	cmd.Stderr = os.Stderr // Route subprocess errors to parent's stderr for debugging

	// Get stdin and stdout pipes
	stdinPipe, err := cmd.StdinPipe()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to create stdin pipe: %w", err)
	}

	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		stdinPipe.Close()
		return nil, nil, nil, fmt.Errorf("failed to create stdout pipe: %w", err)
	}

	// Start the subprocess
	if err := cmd.Start(); err != nil {
		stdinPipe.Close()
		stdoutPipe.Close()
		return nil, nil, nil, fmt.Errorf("failed to start tunnel worker: %w", err)
	}

	log.Debug().
		Str("targetAddr", targetAddr).
		Msg("Spawned tunnel worker subprocess (macOS - no credential demotion).")

	return cmd, stdinPipe, stdoutPipe, nil
}
