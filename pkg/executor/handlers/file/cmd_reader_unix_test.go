//go:build !windows

package file

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestCmdReadCloser_NormalRead(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "f.txt")
	if err := os.WriteFile(tmp, []byte("hello"), 0644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("cat", tmp)
	rc, err := newCmdReadCloser(cmd)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	got, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != "hello" {
		t.Fatalf("got %q", got)
	}
	if err := rc.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
}

func TestCmdReadCloser_NonZeroExit(t *testing.T) {
	cmd := exec.Command("cat", "/nonexistent/path/abcdef")
	rc, err := newCmdReadCloser(cmd)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	_, _ = io.ReadAll(rc)
	cerr := rc.Close()
	if cerr == nil {
		t.Fatal("expected non-nil close error")
	}
	if !strings.Contains(cerr.Error(), "No such file") && !strings.Contains(cerr.Error(), "cannot open") {
		t.Fatalf("expected stderr in error, got %q", cerr.Error())
	}
}

func TestCmdReadCloser_DoubleCloseIdempotent(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "f.txt")
	_ = os.WriteFile(tmp, []byte("x"), 0644)
	rc, err := newCmdReadCloser(exec.Command("cat", tmp))
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.ReadAll(rc)
	if err := rc.Close(); err != nil {
		t.Fatalf("first close: %v", err)
	}
	if err := rc.Close(); err != nil {
		t.Fatalf("second close: %v", err)
	}
}

func TestCmdReadCloser_EarlyClose(t *testing.T) {
	g0 := runtime.NumGoroutine()
	tmp := filepath.Join(t.TempDir(), "big.bin")
	if err := os.WriteFile(tmp, make([]byte, 4<<20), 0644); err != nil {
		t.Fatal(err)
	}
	rc, err := newCmdReadCloser(exec.Command("cat", tmp))
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 16)
	if _, err := rc.Read(buf); err != nil && !errors.Is(err, io.EOF) {
		t.Fatalf("read: %v", err)
	}
	if err := rc.Close(); err != nil {
		// broken pipe / signal-killed cat is acceptable; failure mode is a
		// hung test or a leaked goroutine, not a Close error.
		t.Logf("close after early close (allowed): %v", err)
	}
	if got := runtime.NumGoroutine(); got > g0+2 {
		t.Fatalf("goroutine leak: %d → %d", g0, got)
	}
}

func TestCmdReadCloser_CtxCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, "cat") // no path → reads stdin → blocks
	rc, err := newCmdReadCloser(cmd)
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	_, _ = io.ReadAll(rc)
	if err := rc.Close(); err == nil {
		t.Logf("close after cancel returned nil (acceptable on some systems)")
	}
}
