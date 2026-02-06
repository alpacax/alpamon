package runner

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"syscall"

	"github.com/rs/zerolog/log"
)

// spawnTunnelDaemon spawns a tunnel daemon subprocess.
// On macOS, credential demotion is not supported, so the subprocess runs as the current user.
func spawnTunnelDaemon(socketPath string) (*exec.Cmd, error) {
	executable, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("failed to get executable path: %w", err)
	}

	cmd := exec.Command(executable, "tunnel-daemon", socketPath)
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start tunnel daemon: %w", err)
	}

	log.Debug().Msgf("Spawned tunnel daemon subprocess for socket %s (macOS - runs as current user).", socketPath)

	return cmd, nil
}

// startCodeServerProcess starts code-server on macOS.
// On macOS, credential demotion is not supported, so the process runs as the current user.
func startCodeServerProcess(ctx context.Context, m *CodeServerManager, userDataDir string) (*exec.Cmd, error) {
	codeServerPath, err := getCodeServerPath()
	if err != nil {
		return nil, err
	}

	args := getCodeServerArgs(m.port, userDataDir)
	cmd := exec.CommandContext(ctx, codeServerPath, args...)
	cmd.Dir = m.homeDir

	cmd.Env = getCodeServerEnv(m.homeDir, false)

	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start code-server: %w", err)
	}

	log.Info().Msgf("code-server process started on port %d (macOS - runs as current user).", m.port)

	return cmd, nil
}
