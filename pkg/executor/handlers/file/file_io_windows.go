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

// writeFileAs streams src into a file directly on Windows (no privilege demotion available).
func writeFileAs(ctx context.Context, path string, src io.Reader, sysProcAttr *syscall.SysProcAttr) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	_, err = io.Copy(f, src)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}
