//go:build !windows

package runner

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"syscall"

	"github.com/rs/zerolog/log"
)

// tunnelDaemonCredential returns nobody's credential when isRoot, or nil so the
// daemon keeps the current user.
func tunnelDaemonCredential(isRoot bool) (*syscall.Credential, error) {
	if !isRoot {
		log.Debug().Msg("Alpamon is not running as root. Tunnel daemon will run as current user.")
		return nil, nil
	}

	usr, err := user.Lookup("nobody")
	if err != nil {
		return nil, fmt.Errorf("failed to lookup nobody user: %w", err)
	}
	uid, gid, err := parseUserCredentials(usr.Uid, usr.Gid)
	if err != nil {
		return nil, fmt.Errorf("failed to parse nobody credentials: %w", err)
	}

	// Groups stays nil so Go calls setgroups(0, NULL), dropping the daemon's
	// supplementary groups; resolving them here would widen what it can reach.
	return &syscall.Credential{Uid: uid, Gid: gid}, nil
}

func parseUserCredentials(uidStr, gidStr string) (uint32, uint32, error) {
	uid, err := strconv.ParseUint(uidStr, 10, 32)
	if err != nil {
		return 0, 0, fmt.Errorf("invalid uid: %w", err)
	}

	gid, err := strconv.ParseUint(gidStr, 10, 32)
	if err != nil {
		return 0, 0, fmt.Errorf("invalid gid: %w", err)
	}

	return uint32(uid), uint32(gid), nil
}

// ensureTunnelSocketDir returns the 0700 tunnel socket dir, refusing a symlinked or foreign-owned one;
// with a daemon credential it is chowned to that user so the daemon can create sockets.
func ensureTunnelSocketDir(daemon *syscall.Credential) (string, error) {
	dir := "/tmp/alpamon-tunnels"
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", fmt.Errorf("failed to create tunnel socket directory: %w", err)
	}

	var daemonUID, daemonGID int
	if daemon != nil {
		daemonUID, daemonGID = int(daemon.Uid), int(daemon.Gid) // release targets are 64-bit, so macOS nobody (4294967294) fits
	}

	allowed, chownUID, chownGID := tunnelSocketDirPolicy(daemon != nil, uint32(os.Geteuid()), daemonUID, daemonGID)
	if err := secureTunnelSocketDir(dir, chownUID, chownGID, allowed...); err != nil {
		return "", err
	}
	return dir, nil
}

// spawnTunnelDaemon starts the tunnel daemon on socketPath in its own process group,
// as daemon when it is non-nil and as the current user otherwise.
func spawnTunnelDaemon(socketPath string, daemon *syscall.Credential) (*exec.Cmd, error) {
	executable, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("failed to get executable path: %w", err)
	}

	cmd := exec.Command(executable, "tunnel-daemon", socketPath)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Credential: daemon}
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start tunnel daemon: %w", err)
	}

	if daemon != nil {
		log.Debug().Msgf("Spawned tunnel daemon for socket %s as uid %d.", socketPath, daemon.Uid)
	} else {
		log.Debug().Msgf("Spawned tunnel daemon for socket %s as the current user.", socketPath)
	}

	return cmd, nil
}
