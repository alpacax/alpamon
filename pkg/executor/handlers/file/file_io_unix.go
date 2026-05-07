//go:build !windows

package file

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"

	"github.com/alpacax/alpamon/pkg/utils"
)

// readFileAs reads a file, using a demoted cat process when privilege demotion is active.
func readFileAs(ctx context.Context, path string, sysProcAttr *syscall.SysProcAttr) (io.ReadCloser, int64, error) {
	if sysProcAttr == nil {
		f, err := os.Open(path)
		if err != nil {
			return nil, 0, err
		}
		st, err := f.Stat()
		if err != nil {
			_ = f.Close()
			return nil, 0, err
		}
		return f, st.Size(), nil
	}
	st, err := os.Stat(path)
	if err != nil {
		return nil, 0, err
	}
	cmd := exec.CommandContext(ctx, "cat", path)
	cmd.SysProcAttr = sysProcAttr
	rc, err := newCmdReadCloser(cmd)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to start cat: %w", err)
	}
	return rc, st.Size(), nil
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
