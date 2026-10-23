package runner

import (
	"context"
	"fmt"
	"os/exec"
)

func startCodeServerProcess(ctx context.Context, m *CodeServerManager, userDataDir string) (*exec.Cmd, error) {
	return nil, fmt.Errorf("code-server is not supported on Windows")
}

func secureCodeServerTree(root string, uid, gid int) error {
	return fmt.Errorf("code-server is not supported on Windows")
}
