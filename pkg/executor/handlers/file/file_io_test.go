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
	"testing"

	"github.com/alpacax/alpamon/v2/pkg/config"
	"github.com/alpacax/alpamon/v2/pkg/executor/handlers/common"
	"github.com/stretchr/testify/require"
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

	require.NoError(t, writeFileAs(context.Background(), path, bytes.NewReader(payload), nil), "writeFileAs")

	got, err := os.ReadFile(path)
	require.NoError(t, err, "ReadFile")
	require.Equal(t, payload, got, "content mismatch")
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
	require.Error(t, err, "expected writeFileAs to return error")

	_, statErr := os.Stat(path)
	require.ErrorIs(t, statErr, os.ErrNotExist, "expected partial file removed")
}

// TestWriteFileAs_DirectPath_CreatesParentDir verifies MkdirAll runs before OpenFile.
func TestWriteFileAs_DirectPath_CreatesParentDir(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "deep", "out.bin")

	require.NoError(t, writeFileAs(context.Background(), path, bytes.NewReader([]byte("ok")), nil), "writeFileAs")
	_, err := os.Stat(path)
	require.NoError(t, err, "expected file at %s", path)
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
	if err != nil {
		require.Same(t, io.EOF, err, "unexpected error")
	}
	require.Equal(t, len(data), n, "bytes read")
	require.False(t, spy.closed, "Close must not be called under limit")
}

// TestLimitedReadCloser_OverLimit verifies an error is returned and Close is called.
func TestLimitedReadCloser_OverLimit(t *testing.T) {
	limit := int64(5)
	lr, spy := newLimitedRC(bytes.Repeat([]byte("x"), 20), limit)

	_, err := lr.Read(make([]byte, 32))
	require.ErrorContains(t, err, "download too large")
	require.True(t, spy.closed, "Close must be called on over-limit")
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
	require.LessOrEqual(t, int64(total), limit+1, "overshoot: limit=%d", limit)
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
	}
	require.ErrorContains(t, err, "download too large")
}
