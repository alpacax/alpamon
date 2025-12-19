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
func spawnTunnelWorker(targetAddr string) (*exec.Cmd, io.WriteCloser, io.ReadCloser, error) {
	executable, err := os.Executable()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to get executable path: %w", err)
	}

	cmd := exec.Command(executable, "tunnel-worker", targetAddr)
	cmd.Stderr = os.Stderr

	stdinPipe, err := cmd.StdinPipe()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to create stdin pipe: %w", err)
	}

	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		stdinPipe.Close()
		return nil, nil, nil, fmt.Errorf("failed to create stdout pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		stdinPipe.Close()
		stdoutPipe.Close()
		return nil, nil, nil, fmt.Errorf("failed to start tunnel worker: %w", err)
	}

	log.Debug().
		Str("targetAddr", targetAddr).
		Msg("Spawned tunnel worker subprocess (macOS - runs as current user).")

	return cmd, stdinPipe, stdoutPipe, nil
}
