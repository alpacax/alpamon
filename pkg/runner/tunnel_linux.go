package runner

import (
	"context"
	"fmt"
	"math"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"syscall"

	"github.com/rs/zerolog/log"
)

func getNobodyCredential() (*syscall.SysProcAttr, error) {
	if os.Getuid() != 0 {
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

	return &syscall.SysProcAttr{
		Credential: &syscall.Credential{
			Uid: uid,
			Gid: gid,
		},
	}, nil
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

// ensureTunnelSocketDir creates and returns the tunnel socket directory with proper ownership.
// Uses 0700 permissions to prevent other users from creating symlinks or files inside.
// When running as root, the directory is chowned to nobody so the daemon can create sockets.
func ensureTunnelSocketDir() (string, error) {
	dir := "/tmp/alpamon-tunnels"
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", fmt.Errorf("failed to create tunnel socket directory: %w", err)
	}

	if os.Getuid() == 0 {
		usr, err := user.Lookup("nobody")
		if err != nil {
			return "", fmt.Errorf("failed to lookup nobody user for socket dir: %w", err)
		}
		uid, gid, err := parseUserCredentials(usr.Uid, usr.Gid)
		if err != nil {
			return "", fmt.Errorf("failed to parse nobody credentials for socket dir: %w", err)
		}
		if uid > math.MaxInt32 || gid > math.MaxInt32 {
			return "", fmt.Errorf("nobody uid/gid exceeds int32 range: uid=%d, gid=%d", uid, gid)
		}
		if err := os.Chown(dir, int(uid), int(gid)); err != nil {
			return "", fmt.Errorf("failed to chown tunnel socket directory: %w", err)
		}
	}

	return dir, nil
}

// spawnTunnelDaemon spawns a tunnel daemon subprocess with nobody credentials.
// The daemon listens on a Unix domain socket and relays multiple connections as goroutines.
func spawnTunnelDaemon(socketPath string) (*exec.Cmd, error) {
	sysProcAttr, err := getNobodyCredential()
	if err != nil {
		return nil, fmt.Errorf("failed to get tunnel daemon credentials: %w", err)
	}

	executable, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("failed to get executable path: %w", err)
	}

	cmd := exec.Command(executable, "tunnel-daemon", socketPath)
	if sysProcAttr == nil {
		sysProcAttr = &syscall.SysProcAttr{}
	}
	sysProcAttr.Setpgid = true
	cmd.SysProcAttr = sysProcAttr
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start tunnel daemon: %w", err)
	}

	log.Debug().Msgf("Spawned tunnel daemon subprocess as nobody user, socket: %s.", socketPath)

	return cmd, nil
}

// startCodeServerProcess starts code-server with user credentials on Linux.
// If running as root, the process is demoted to the specified user.
func startCodeServerProcess(ctx context.Context, m *CodeServerManager, userDataDir string) (*exec.Cmd, error) {
	codeServerPath, err := getCodeServerPath()
	if err != nil {
		return nil, err
	}

	args := getCodeServerArgs(m.port, userDataDir)
	cmd := exec.CommandContext(ctx, codeServerPath, args...)
	cmd.Dir = m.homeDir

	cmd.Env = getCodeServerEnv(m.homeDir, true)

	sysProcAttr, err := getCodeServerCredential(m.username, m.groupname)
	if err != nil {
		return nil, fmt.Errorf("failed to get user credentials: %w", err)
	}
	if sysProcAttr == nil {
		sysProcAttr = &syscall.SysProcAttr{}
	}
	sysProcAttr.Setpgid = true
	cmd.SysProcAttr = sysProcAttr

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start code-server: %w", err)
	}

	log.Info().Msgf("code-server process started on port %d (user: %s, group: %s).", m.port, m.username, m.groupname)

	return cmd, nil
}

// getCodeServerCredential returns SysProcAttr for running code-server as the specified user.
func getCodeServerCredential(username, groupname string) (*syscall.SysProcAttr, error) {
	if os.Getuid() != 0 {
		log.Debug().Msg("Alpamon is not running as root. code-server will run as current user.")
		return nil, nil
	}

	usr, err := user.Lookup(username)
	if err != nil {
		return nil, fmt.Errorf("user %s not found: %w", username, err)
	}

	// Use user's primary group if groupname is empty
	gidStr := usr.Gid
	if groupname != "" {
		group, err := user.LookupGroup(groupname)
		if err != nil {
			return nil, fmt.Errorf("group %s not found: %w", groupname, err)
		}
		gidStr = group.Gid
	}

	uid, gid, err := parseUserCredentials(usr.Uid, gidStr)
	if err != nil {
		return nil, err
	}

	groups := parseGroupIDs(usr)

	log.Debug().Msgf("Demoting code-server to user %s (group: %s).", username, groupname)

	return &syscall.SysProcAttr{
		Credential: &syscall.Credential{
			Uid:    uid,
			Gid:    gid,
			Groups: groups,
		},
	}, nil
}

func parseGroupIDs(usr *user.User) []uint32 {
	groupIds, err := usr.GroupIds()
	if err != nil {
		return nil
	}

	groups := make([]uint32, 0, len(groupIds))
	for _, gidStr := range groupIds {
		gid, err := strconv.ParseUint(gidStr, 10, 32)
		if err != nil {
			continue
		}
		groups = append(groups, uint32(gid))
	}
	return groups
}
