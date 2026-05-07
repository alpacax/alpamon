package file

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

// readFileAs reads a file directly on Windows (no privilege demotion available).
func readFileAs(ctx context.Context, path string, sysProcAttr *syscall.SysProcAttr) (io.ReadCloser, int64, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, 0, err
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, 0, err
	}
	return f, st.Size(), nil
}

// writeFileAs writes a file directly on Windows (no privilege demotion available).
func writeFileAs(ctx context.Context, path string, content []byte, sysProcAttr *syscall.SysProcAttr) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	return os.WriteFile(path, content, 0644)
}
