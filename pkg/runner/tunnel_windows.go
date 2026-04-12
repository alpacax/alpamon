package runner

import (
	"context"
	"fmt"
	"os/exec"
)

func ensureTunnelSocketDir() (string, error) {
	return "", fmt.Errorf("tunnel is not supported on Windows")
}

func spawnTunnelDaemon(socketPath string) (*exec.Cmd, error) {
	return nil, fmt.Errorf("tunnel is not supported on Windows")
}

func startCodeServerProcess(ctx context.Context, m *CodeServerManager, userDataDir string) (*exec.Cmd, error) {
	return nil, fmt.Errorf("code-server is not supported on Windows")
}
