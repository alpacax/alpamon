package runner

import (
	"context"
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

	log.Debug().Msgf("Spawned tunnel worker subprocess for %s (macOS - runs as current user).", targetAddr)

	return cmd, stdinPipe, stdoutPipe, nil
}

// startCodeServerProcess starts code-server on macOS.
// On macOS, credential demotion is not supported, so the process runs as the current user.
func startCodeServerProcess(ctx context.Context, port int, userDataDir, username, groupname, homeDir string) (*exec.Cmd, error) {
	codeServerPath, err := getCodeServerPath()
	if err != nil {
		return nil, err
	}

	args := getCodeServerArgs(port, userDataDir)
	cmd := exec.CommandContext(ctx, codeServerPath, args...)
	cmd.Dir = homeDir

	cmd.Env = append(os.Environ(),
		fmt.Sprintf("HOME=%s", homeDir),
	)

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start code-server: %w", err)
	}

	log.Info().Msgf("code-server process started on port %d (macOS - runs as current user).", port)

	return cmd, nil
}
