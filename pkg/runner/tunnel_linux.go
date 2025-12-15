package runner

import (
	"fmt"
	"io"
	"os"
	"os/exec"

	"github.com/rs/zerolog/log"
)

// spawnTunnelWorker spawns a tunnel worker subprocess with demoted user credentials.
// The subprocess connects to the target address and relays data via stdin/stdout.
func spawnTunnelWorker(username, groupname, targetAddr string) (*exec.Cmd, io.WriteCloser, io.ReadCloser, error) {
	// Get demoted credentials using existing demoteFtp function
	sysProcAttr, _, err := demoteFtp(username, groupname)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to demote credentials: %w", err)
	}

	// Get current executable path
	executable, err := os.Executable()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to get executable path: %w", err)
	}

	// Create command for tunnel worker subprocess
	cmd := exec.Command(executable, "tunnel-worker", targetAddr)
	cmd.SysProcAttr = sysProcAttr
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
		Str("username", username).
		Str("groupname", groupname).
		Str("targetAddr", targetAddr).
		Msg("Spawned tunnel worker subprocess with demoted credentials.")

	return cmd, stdinPipe, stdoutPipe, nil
}
