package runner

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"syscall"
)

func startCodeServerProcess(ctx context.Context, m *CodeServerManager, userDataDir string) (*exec.Cmd, error) {
	return nil, fmt.Errorf("code-server is not supported on Windows")
}

func installRootOwnedCodeServer(prefix string, uid, gid int, install func() error) error {
	return fmt.Errorf("code-server is not supported on Windows")
}

func prepareEditorSocketDir(m *CodeServerManager) error {
	return fmt.Errorf("code-server is not supported on Windows")
}

func validateEditorPeer(conn *net.UnixConn, attr *syscall.SysProcAttr) error {
	return fmt.Errorf("code-server is not supported on Windows")
}
