package runner

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"

	"github.com/rs/zerolog/log"
)

func getTunnelWorkerCredential() (*syscall.SysProcAttr, error) {
	if os.Getuid() != 0 {
		log.Debug().Msg("Alpamon is not running as root. Tunnel worker will run as current user.")
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

	log.Debug().Msgf("Spawned tunnel worker subprocess as nobody user for %s.", targetAddr)

	return cmd, stdinPipe, stdoutPipe, nil
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

	cmd.Env = append(os.Environ(),
		fmt.Sprintf("HOME=%s", m.homeDir),
		fmt.Sprintf("XDG_DATA_HOME=%s", filepath.Join(m.homeDir, ".local", "share")),
		fmt.Sprintf("XDG_CONFIG_HOME=%s", filepath.Join(m.homeDir, ".config")),
	)

	sysProcAttr, err := getCodeServerCredential(m.username, m.groupname)
	if err != nil {
		return nil, fmt.Errorf("failed to get user credentials: %w", err)
	}
	if sysProcAttr != nil {
		cmd.SysProcAttr = sysProcAttr
	}

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

	group, err := user.LookupGroup(groupname)
	if err != nil {
		return nil, fmt.Errorf("group %s not found: %w", groupname, err)
	}

	uid, gid, err := parseUserCredentials(usr.Uid, group.Gid)
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
