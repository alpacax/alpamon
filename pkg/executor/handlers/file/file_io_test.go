package file

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// failingReader emits payload on first Read, then returns err on the next call.
// io.Copy writes the first chunk, so the partial file exists when err surfaces.
type failingReader struct {
	payload []byte
	served  bool
	err     error
}

func (r *failingReader) Read(p []byte) (int, error) {
	if !r.served {
		n := copy(p, r.payload)
		r.served = true
		return n, nil
	}
	return 0, r.err
}

// TestWriteFileAs_DirectPath_Success covers the happy path on both Unix and Windows.
func TestWriteFileAs_DirectPath_Success(t *testing.T) {
	path := filepath.Join(t.TempDir(), "out.bin")
	payload := []byte("hello world")

	if err := writeFileAs(context.Background(), path, bytes.NewReader(payload), nil); err != nil {
		t.Fatalf("writeFileAs: %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("content mismatch: got %q want %q", got, payload)
	}
}

// TestWriteFileAs_DirectPath_RemovesPartialOnReadError verifies the cleanup branch:
// once src errors mid-stream, the partial file must be removed so a retry
// isn't blocked by AllowOverwrite=false.
func TestWriteFileAs_DirectPath_RemovesPartialOnReadError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "out.bin")
	src := &failingReader{
		payload: bytes.Repeat([]byte("x"), 4096),
		err:     errors.New("simulated stream failure"),
	}

	err := writeFileAs(context.Background(), path, src, nil)
	if err == nil {
		t.Fatal("expected writeFileAs to return error")
	}

	if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
		t.Fatalf("expected partial file removed, stat err = %v", statErr)
	}
}

// TestWriteFileAs_DirectPath_CreatesParentDir verifies MkdirAll runs before OpenFile.
func TestWriteFileAs_DirectPath_CreatesParentDir(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "deep", "out.bin")

	if err := writeFileAs(context.Background(), path, bytes.NewReader([]byte("ok")), nil); err != nil {
		t.Fatalf("writeFileAs: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("expected file at %s, got %v", path, err)
	}
}
