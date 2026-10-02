//go:build !windows

package file

import (
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCmdReadCloser_NormalRead(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "f.txt")
	require.NoError(t, os.WriteFile(tmp, []byte("hello"), 0644))
	cmd := exec.Command("cat", tmp)
	rc, err := newCmdReadCloser(cmd)
	require.NoError(t, err, "new")
	got, err := io.ReadAll(rc)
	require.NoError(t, err, "read")
	require.Equal(t, "hello", string(got))
	require.NoError(t, rc.Close(), "close")
}

func TestCmdReadCloser_NonZeroExit(t *testing.T) {
	cmd := exec.Command("cat", "/nonexistent/path/abcdef")
	rc, err := newCmdReadCloser(cmd)
	require.NoError(t, err, "new")
	_, _ = io.ReadAll(rc)
	cerr := rc.Close()
	require.Error(t, cerr, "expected non-nil close error")
	require.Regexp(t, "No such file|cannot open", cerr.Error(), "expected stderr in error")
}

func TestCmdReadCloser_DoubleCloseIdempotent(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "f.txt")
	_ = os.WriteFile(tmp, []byte("x"), 0644)
	rc, err := newCmdReadCloser(exec.Command("cat", tmp))
	require.NoError(t, err)
	_, _ = io.ReadAll(rc)
	require.NoError(t, rc.Close(), "first close")
	require.NoError(t, rc.Close(), "second close")
}

func TestCmdReadCloser_EarlyClose(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "big.bin")
	require.NoError(t, os.WriteFile(tmp, make([]byte, 4<<20), 0644))
	rc, err := newCmdReadCloser(exec.Command("cat", tmp))
	require.NoError(t, err)
	// Safety net: a failed require below would skip the explicit Close and leak the unreaped cat
	// process. Close() is idempotent, so the tested early Close still stands.
	defer func() { _ = rc.Close() }()
	buf := make([]byte, 16)
	if _, err := rc.Read(buf); err != nil {
		require.ErrorIs(t, err, io.EOF, "read")
	}
	// Close before EOF: Close() calls cmd.Wait(), which reaps the process and joins
	// os/exec's stderr-copy goroutine, so nothing leaks. A regression (hang or unreaped
	// process) surfaces as a test timeout, not a goroutine-count check.
	if err := rc.Close(); err != nil {
		// broken pipe / signal-killed cat is acceptable.
		t.Logf("close after early close (allowed): %v", err)
	}
}

func TestCmdReadCloser_CtxCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, "cat") // no path → reads stdin → blocks
	rc, err := newCmdReadCloser(cmd)
	require.NoError(t, err)
	cancel()
	_, _ = io.ReadAll(rc)
	if err := rc.Close(); err == nil {
		t.Logf("close after cancel returned nil (acceptable on some systems)")
	}
}
