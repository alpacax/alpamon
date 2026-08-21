package file

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"io"
	"mime"
	"mime/multipart"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type errReader struct {
	r          io.Reader
	failAt     int
	read       int
	closeCnt   int
	closeErr   error
	closed     chan struct{} // if set, Close() closes it once to signal the producer goroutine reached its src.Close defer
	closedDone bool          // guards close(closed) so a repeated Close is a no-op instead of a panic
}

func (e *errReader) Read(p []byte) (int, error) {
	if e.read >= e.failAt {
		return 0, errors.New("synthetic")
	}
	n, err := e.r.Read(p)
	e.read += n
	if e.read > e.failAt {
		n -= e.read - e.failAt
		e.read = e.failAt
	}
	return n, err
}

func (e *errReader) Close() error {
	e.closeCnt++
	if e.closed != nil && !e.closedDone {
		e.closedDone = true
		close(e.closed)
	}
	return e.closeErr
}

// requireMultipartReader parses ct as a multipart/form-data content type and
// returns a reader over body, failing the test when either step does not hold.
func requireMultipartReader(t *testing.T, body io.Reader, ct string) *multipart.Reader {
	t.Helper()
	mt, params, err := mime.ParseMediaType(ct)
	require.NoError(t, err, "ct=%q", ct)
	require.Equal(t, "multipart/form-data", mt)
	return multipart.NewReader(body, params["boundary"])
}

func TestBuildMultipartStream_Roundtrip(t *testing.T) {
	payload := bytes.Repeat([]byte{0xAB}, 1<<20)
	src := io.NopCloser(bytes.NewReader(payload))
	body, ct, _, err := buildMultipartStream(src, "f.bin", false, -1)
	require.NoError(t, err)
	defer func() { _ = body.Close() }()

	mr := requireMultipartReader(t, body, ct)
	part, err := mr.NextPart()
	require.NoError(t, err)
	assert.Equal(t, "content", part.FormName())
	assert.Equal(t, "f.bin", part.FileName())

	got := sha256.New()
	_, err = io.Copy(got, part)
	require.NoError(t, err)
	want := sha256.Sum256(payload)
	assert.Equal(t, want[:], got.Sum(nil), "payload digest mismatch")

	_, err = mr.NextPart()
	assert.ErrorIs(t, err, io.EOF)
}

func TestBuildMultipartStream_Recursive(t *testing.T) {
	src := io.NopCloser(strings.NewReader("zip-data"))
	body, ct, _, err := buildMultipartStream(src, "tree.zip", true, -1)
	require.NoError(t, err)
	defer func() { _ = body.Close() }()

	mr := requireMultipartReader(t, body, ct)
	sawName := false
	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		require.NoError(t, err)
		if part.FormName() == "name" {
			data, _ := io.ReadAll(part)
			assert.Equal(t, "tree.zip", string(data))
			sawName = true
		}
	}
	assert.True(t, sawName, "expected name field for recursive upload")
}

func TestBuildMultipartStream_SrcErrorPropagates(t *testing.T) {
	er := &errReader{r: bytes.NewReader(bytes.Repeat([]byte{1}, 1024)), failAt: 256}
	body, _, _, err := buildMultipartStream(er, "f", false, -1)
	require.NoError(t, err)

	_, err = io.Copy(io.Discard, body)
	assert.ErrorContains(t, err, "synthetic")

	_ = body.Close()
	assert.NotZero(t, er.closeCnt, "src.Close() was not called")
}

// TestBuildMultipartStream_SrcCloseErrorPropagates exercises the demoted-cat
// failure mode for streaming paths: Read returns a clean EOF (cat is done) but
// Close returns a non-nil exit error (e.g., EACCES collected by cmdReadCloser
// via cmd.Wait). The producer goroutine must surface that close error to the
// reader; otherwise the upload would silently complete with an empty/truncated
// payload. Buffered path has its own test (close error returned synchronously
// before body handoff).
func TestBuildMultipartStream_SrcCloseErrorPropagates(t *testing.T) {
	for _, tc := range []struct {
		name string
		size int
		hint int64
	}{
		{"large_path", 7, -1},
		{"small_path", 128 << 10, 128 << 10}, // hint > multipartBufferedThreshold (64 KiB) to hit io.Pipe small path
	} {
		t.Run(tc.name, func(t *testing.T) {
			payload := bytes.Repeat([]byte{0x42}, tc.size)
			er := &errReader{
				r:        bytes.NewReader(payload),
				failAt:   1 << 30,
				closeErr: errors.New("synthetic-close-fail"),
			}
			body, _, _, err := buildMultipartStream(er, "f.bin", false, tc.hint)
			require.NoError(t, err)

			_, err = io.Copy(io.Discard, body)
			assert.ErrorContains(t, err, "synthetic-close-fail", "expected src.Close error to propagate")

			_ = body.Close()
		})
	}
}

func TestBuildMultipartStream_EarlyCloseNoLeak(t *testing.T) {
	// Wait on the producer goroutine's src.Close defer instead of polling a
	// goroutine count. Nothing after src.Close in that teardown can block (only
	// pool puts and a pipe close remain), so the signal proves it exits.
	er := &errReader{r: bytes.NewReader(bytes.Repeat([]byte{1}, 4<<20)), failAt: 1 << 30, closed: make(chan struct{})}
	body, _, _, err := buildMultipartStream(er, "f", false, -1)
	require.NoError(t, err, "buildMultipartStream")
	buf := make([]byte, 64)
	_, _ = body.Read(buf)
	_ = body.Close()
	select {
	case <-er.closed:
	case <-time.After(5 * time.Second):
		t.Fatal("producer goroutine did not exit after early body close")
	}
}

// TestBuildMultipartStream_SmallPath_Roundtrip verifies that the small-file
// path (hint < multipartPipeBufSize, currently 4 MiB) produces a well-formed
// multipart body with correct payload.
func TestBuildMultipartStream_SmallPath_Roundtrip(t *testing.T) {
	payload := bytes.Repeat([]byte{0xCD}, 512<<10) // 512 KiB — well below multipartPipeBufSize (4 MiB)
	src := io.NopCloser(bytes.NewReader(payload))
	body, ct, _, err := buildMultipartStream(src, "small.bin", false, int64(len(payload)))
	require.NoError(t, err)
	defer func() { _ = body.Close() }()

	mr := requireMultipartReader(t, body, ct)
	part, err := mr.NextPart()
	require.NoError(t, err)
	assert.Equal(t, multipartFieldContent, part.FormName())
	assert.Equal(t, "small.bin", part.FileName())

	got := sha256.New()
	_, err = io.Copy(got, part)
	require.NoError(t, err)
	want := sha256.Sum256(payload)
	assert.Equal(t, want[:], got.Sum(nil), "payload digest mismatch")

	_, err = mr.NextPart()
	assert.ErrorIs(t, err, io.EOF)
}

// TestBuildMultipartStream_BufferedPath_Roundtrip verifies the buffered path
// (hint <= multipartBufferedThreshold) produces a well-formed multipart body
// with correct payload, exact ContentLength, and synchronous src.Close.
func TestBuildMultipartStream_BufferedPath_Roundtrip(t *testing.T) {
	for _, tc := range []struct {
		name      string
		size      int
		recursive bool
	}{
		{"single_1KB", 1 << 10, false},
		{"single_at_threshold", multipartBufferedThreshold, false},
		{"recursive_1KB", 1 << 10, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			payload := bytes.Repeat([]byte{0xCD}, tc.size)
			er := &errReader{r: bytes.NewReader(payload), failAt: 1 << 30}
			body, ct, contentLength, err := buildMultipartStream(er, "f.bin", tc.recursive, int64(tc.size))
			require.NoError(t, err)
			defer func() { _ = body.Close() }()

			assert.Positive(t, contentLength)
			assert.NotZero(t, er.closeCnt, "expected src.Close to be called synchronously")

			// Drain into a buffer so we can both verify wire size and parse
			// (boundary is per-call, so a second buildMultipartStream() would
			// have a different boundary than the ct we captured here).
			var captured bytes.Buffer
			n, err := captured.ReadFrom(body)
			require.NoError(t, err)
			assert.Equal(t, contentLength, n, "wire size must match contentLength")

			part, err := requireMultipartReader(t, &captured, ct).NextPart()
			require.NoError(t, err)
			assert.Equal(t, multipartFieldContent, part.FormName())
			assert.Equal(t, "f.bin", part.FileName())

			got := sha256.New()
			_, err = io.Copy(got, part)
			require.NoError(t, err)
			want := sha256.Sum256(payload)
			assert.Equal(t, want[:], got.Sum(nil), "payload digest mismatch")
		})
	}
}

// TestBuildMultipartStream_BufferedPath_SrcCloseErrorPropagates verifies the
// buffered path surfaces src.Close() errors (e.g., demoted-cat non-zero exit
// from cmdReadCloser) instead of silently returning a successful body.
func TestBuildMultipartStream_BufferedPath_SrcCloseErrorPropagates(t *testing.T) {
	er := &errReader{
		r:        bytes.NewReader([]byte("payload")),
		failAt:   1 << 30,
		closeErr: errors.New("synthetic-close-fail"),
	}
	_, _, _, err := buildMultipartStream(er, "f.bin", false, int64(len("payload")))
	assert.ErrorContains(t, err, "synthetic-close-fail", "expected close error to propagate")
}

// TestBuildMultipartStream_SmallPathContentLengthMatchesWire verifies the
// precomputed contentLength equals the actual rendered byte count for the
// small path (single + recursive). A mismatch would cause the server to
// truncate the body or hang waiting for more bytes.
func TestBuildMultipartStream_SmallPathContentLengthMatchesWire(t *testing.T) {
	for _, tc := range []struct {
		name      string
		size      int
		recursive bool
	}{
		{"single", 64 << 10, false},
		{"recursive", 64 << 10, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			payload := bytes.Repeat([]byte{0xEE}, tc.size)
			src := io.NopCloser(bytes.NewReader(payload))
			body, _, contentLength, err := buildMultipartStream(src, "f.bin", tc.recursive, int64(tc.size))
			require.NoError(t, err)
			defer func() { _ = body.Close() }()

			assert.Positive(t, contentLength)
			n, err := io.Copy(io.Discard, body)
			require.NoError(t, err)
			assert.Equal(t, contentLength, n, "wire size must match precomputed contentLength")
		})
	}
}

// TestBuildMultipartStream_LargePathReturnsMinusOne verifies the large path
// always reports contentLength=-1 (chunked TE) even when size is known. See
// buildMultipartStream doc for why finite ContentLength on the large path
// triggers a regression via net/http's io.LimitReader wrap.
func TestBuildMultipartStream_LargePathReturnsMinusOne(t *testing.T) {
	for _, tc := range []struct {
		name string
		hint int64
	}{
		{"unknown", -1},
		{"known_large", 5 << 20},
	} {
		t.Run(tc.name, func(t *testing.T) {
			src := io.NopCloser(bytes.NewReader(bytes.Repeat([]byte{1}, 5<<20)))
			body, _, contentLength, err := buildMultipartStream(src, "f.bin", false, tc.hint)
			require.NoError(t, err)
			defer func() { _ = body.Close() }()
			assert.Equal(t, int64(-1), contentLength)
		})
	}
}

// TestBuildMultipartStream_SmallPath_Recursive verifies the small-file path
// emits the "name" field when isRecursive=true.
func TestBuildMultipartStream_SmallPath_Recursive(t *testing.T) {
	payload := []byte("small-zip-data")
	src := io.NopCloser(bytes.NewReader(payload))
	body, ct, _, err := buildMultipartStream(src, "arch.zip", true, int64(len(payload)))
	require.NoError(t, err)
	defer func() { _ = body.Close() }()

	mr := requireMultipartReader(t, body, ct)
	sawName := false
	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		require.NoError(t, err)
		if part.FormName() == multipartFieldName {
			data, _ := io.ReadAll(part)
			assert.Equal(t, "arch.zip", string(data))
			sawName = true
		}
	}
	assert.True(t, sawName, "expected name field for recursive small upload")
}
