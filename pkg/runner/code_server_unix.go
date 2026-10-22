//go:build !windows

package runner

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"syscall"

	"github.com/rs/zerolog/log"
)

// startCodeServerProcess starts code-server as the identity NewCodeServerManager resolved.
func startCodeServerProcess(ctx context.Context, m *CodeServerManager, userDataDir string) (*exec.Cmd, error) {
	codeServerPath, err := getCodeServerPath()
	if err != nil {
		return nil, err
	}

	args := getCodeServerArgs(m.port, userDataDir)
	cmd := exec.CommandContext(ctx, codeServerPath, args...)
	cmd.Dir = m.homeDir

	cmd.Env = getCodeServerEnv(m.homeDir, runtime.GOOS != "darwin")

	attr := syscall.SysProcAttr{}
	if m.procAttr != nil {
		attr = *m.procAttr
	}
	attr.Setpgid = true
	cmd.SysProcAttr = &attr

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start code-server: %w", err)
	}

	if m.procAttr != nil {
		log.Info().Msgf("code-server process started on port %d (user: %s, group: %s).", m.port, m.username, m.groupname)
	} else {
		log.Info().Msgf("code-server process started on port %d as the current user.", m.port)
	}

	return cmd, nil
}
