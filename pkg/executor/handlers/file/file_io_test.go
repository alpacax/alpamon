package file

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alpacax/alpamon/v2/pkg/config"
	"github.com/alpacax/alpamon/v2/pkg/executor/handlers/common"
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

// closeSpy wraps a Reader and records whether Close was called.
type closeSpy struct {
	io.Reader
	closed bool
}

func (c *closeSpy) Close() error {
	c.closed = true
	return nil
}

func newLimitedRC(data []byte, limit int64) (*limitedReadCloser, *closeSpy) {
	spy := &closeSpy{Reader: bytes.NewReader(data)}
	return &limitedReadCloser{r: io.LimitReader(spy, limit+1), rc: spy, limit: limit}, spy
}

// TestLimitedReadCloser_UnderLimit verifies all bytes are delivered and Close is not called.
func TestLimitedReadCloser_UnderLimit(t *testing.T) {
	data := []byte("hello")
	lr, spy := newLimitedRC(data, 10)

	buf := make([]byte, 32)
	n, err := lr.Read(buf)
	if err != nil && err != io.EOF {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != len(data) {
		t.Fatalf("got %d bytes, want %d", n, len(data))
	}
	if spy.closed {
		t.Fatal("Close must not be called under limit")
	}
}

// TestLimitedReadCloser_OverLimit verifies an error is returned and Close is called.
func TestLimitedReadCloser_OverLimit(t *testing.T) {
	limit := int64(5)
	lr, spy := newLimitedRC(bytes.Repeat([]byte("x"), 20), limit)

	_, err := lr.Read(make([]byte, 32))
	if err == nil {
		t.Fatal("expected error for over-limit read")
	}
	if !strings.Contains(err.Error(), "download too large") {
		t.Fatalf("unexpected error message: %v", err)
	}
	if !spy.closed {
		t.Fatal("Close must be called on over-limit")
	}
}

// TestLimitedReadCloser_OvershootAtMostOneByte verifies that io.LimitReader(rc, limit+1)
// caps the total bytes delivered to at most limit+1.
func TestLimitedReadCloser_OvershootAtMostOneByte(t *testing.T) {
	limit := int64(10)
	lr, _ := newLimitedRC(bytes.Repeat([]byte("x"), 20), limit)

	var total int
	buf := make([]byte, 32*1024)
	for {
		n, err := lr.Read(buf)
		total += n
		if err != nil {
			break
		}
	}
	if int64(total) > limit+1 {
		t.Fatalf("overshoot: read %d bytes, limit=%d (max limit+1=%d)", total, limit, limit+1)
	}
}

// TestFetchFromURL_ContentLengthExceedsLimit verifies the upfront Content-Length check.
func TestFetchFromURL_ContentLengthExceedsLimit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "1000")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	orig := config.GlobalSettings.MaxDownloadBytes
	config.GlobalSettings.MaxDownloadBytes = 100
	defer func() { config.GlobalSettings.MaxDownloadBytes = orig }()

	h := NewFileHandler(common.NewMockCommandExecutor(t), nil)
	rc, err := h.fetchFromURL(context.Background(), srv.URL)
	if err == nil {
		_ = rc.Close()
		t.Fatal("expected error when Content-Length exceeds limit")
	}
	if !strings.Contains(err.Error(), "download too large") {
		t.Fatalf("unexpected error: %v", err)
	}
}
