package file

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
)

// readFileAs reads a file directly on Windows (no privilege demotion available).
func readFileAs(ctx context.Context, path string, sysProcAttr *syscall.SysProcAttr) ([]byte, error) {
	return os.ReadFile(path)
}

// writeFileAs writes a file directly on Windows (no privilege demotion available).
func writeFileAs(ctx context.Context, path string, content []byte, sysProcAttr *syscall.SysProcAttr) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	return os.WriteFile(path, content, 0644)
}
