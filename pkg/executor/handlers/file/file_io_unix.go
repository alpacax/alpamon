//go:build !windows

package file

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"

	"github.com/alpacax/alpamon/pkg/utils"
)

// readFileAs reads a file, using a demoted cat process when privilege demotion is active.
func readFileAs(ctx context.Context, path string, sysProcAttr *syscall.SysProcAttr) ([]byte, error) {
	if sysProcAttr == nil {
		return os.ReadFile(path)
	}
	cmd := exec.CommandContext(ctx, "cat", path)
	cmd.SysProcAttr = sysProcAttr
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to read file as demoted user: %w", err)
	}
	return output, nil
}

// writeFileAs writes a file, using a demoted tee process when privilege demotion is active.
func writeFileAs(ctx context.Context, path string, content []byte, sysProcAttr *syscall.SysProcAttr) error {
	if sysProcAttr == nil {
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			return err
		}
		return os.WriteFile(path, content, 0644)
	}
	cmd := exec.CommandContext(ctx, "sh", "-c", fmt.Sprintf("tee %s > /dev/null", utils.Quote(path)))
	cmd.SysProcAttr = sysProcAttr
	cmd.Stdin = bytes.NewReader(content)
	_, err := cmd.Output()
	return err
}
