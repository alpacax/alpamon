package runner

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"syscall"

	"github.com/rs/zerolog/log"
)

func getTunnelWorkerCredential() (*syscall.SysProcAttr, error) {
	currentUid := os.Getuid()
	if currentUid != 0 {
		log.Debug().Msg("Alpamon is not running as root. Tunnel worker will run as current user.")
		return nil, nil
	}

	usr, err := user.Lookup("nobody")
	if err != nil {
		return nil, fmt.Errorf("failed to lookup nobody user: %w", err)
	}

	uid, err := strconv.ParseUint(usr.Uid, 10, 32)
	if err != nil {
		return nil, fmt.Errorf("failed to parse nobody uid: %w", err)
	}

	gid, err := strconv.ParseUint(usr.Gid, 10, 32)
	if err != nil {
		return nil, fmt.Errorf("failed to parse nobody gid: %w", err)
	}

	return &syscall.SysProcAttr{
		Credential: &syscall.Credential{
			Uid: uint32(uid),
			Gid: uint32(gid),
		},
	}, nil
}

// spawnTunnelWorker spawns a tunnel worker subprocess with nobody credentials.
// The subprocess connects to the target address and relays data via stdin/stdout.
func spawnTunnelWorker(targetAddr string) (*exec.Cmd, io.WriteCloser, io.ReadCloser, error) {
	sysProcAttr, err := getTunnelWorkerCredential()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to get tunnel worker credentials: %w", err)
	}

	executable, err := os.Executable()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to get executable path: %w", err)
	}

	cmd := exec.Command(executable, "tunnel-worker", targetAddr)
	cmd.SysProcAttr = sysProcAttr
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
		Msg("Spawned tunnel worker subprocess as nobody user.")

	return cmd, stdinPipe, stdoutPipe, nil
}
