package file

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"io"
	"mime"
	"mime/multipart"
	"runtime"
	"strings"
	"testing"
	"time"
)

type errReader struct {
	r        io.Reader
	failAt   int
	read     int
	closeCnt int
	closeErr error
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

func (e *errReader) Close() error { e.closeCnt++; return e.closeErr }

func TestBuildMultipartStream_Roundtrip(t *testing.T) {
	payload := bytes.Repeat([]byte{0xAB}, 1<<20)
	src := io.NopCloser(bytes.NewReader(payload))
	body, ct, _, err := buildMultipartStream(src, "f.bin", false, -1)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = body.Close() }()
	mt, params, err := mime.ParseMediaType(ct)
	if err != nil || mt != "multipart/form-data" {
		t.Fatalf("ct=%q err=%v", ct, err)
	}
	mr := multipart.NewReader(body, params["boundary"])
	part, err := mr.NextPart()
	if err != nil {
		t.Fatal(err)
	}
	if part.FormName() != "content" || part.FileName() != "f.bin" {
		t.Fatalf("name=%q file=%q", part.FormName(), part.FileName())
	}
	got := sha256.New()
	if _, err := io.Copy(got, part); err != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256(payload)
	if !bytes.Equal(got.Sum(nil), want[:]) {
		t.Fatal("payload digest mismatch")
	}
	if _, err := mr.NextPart(); err != io.EOF {
		t.Fatalf("expected EOF, got %v", err)
	}
}

func TestBuildMultipartStream_Recursive(t *testing.T) {
	src := io.NopCloser(strings.NewReader("zip-data"))
	body, ct, _, err := buildMultipartStream(src, "tree.zip", true, -1)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = body.Close() }()
	_, params, _ := mime.ParseMediaType(ct)
	mr := multipart.NewReader(body, params["boundary"])
	sawName := false
	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if part.FormName() == "name" {
			data, _ := io.ReadAll(part)
			if string(data) != "tree.zip" {
				t.Fatalf("name=%q", data)
			}
			sawName = true
		}
	}
	if !sawName {
		t.Fatal("expected name field for recursive upload")
	}
}

func TestBuildMultipartStream_SrcErrorPropagates(t *testing.T) {
	er := &errReader{r: bytes.NewReader(bytes.Repeat([]byte{1}, 1024)), failAt: 256}
	body, _, _, err := buildMultipartStream(er, "f", false, -1)
	if err != nil {
		t.Fatal(err)
	}
	_, err = io.Copy(io.Discard, body)
	if err == nil || !strings.Contains(err.Error(), "synthetic") {
		t.Fatalf("expected synthetic error, got %v", err)
	}
	_ = body.Close()
	if er.closeCnt == 0 {
		t.Fatal("src.Close() was not called")
	}
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
			if err != nil {
				t.Fatal(err)
			}
			_, err = io.Copy(io.Discard, body)
			if err == nil || !strings.Contains(err.Error(), "synthetic-close-fail") {
				t.Fatalf("expected src.Close error to propagate, got %v", err)
			}
			_ = body.Close()
		})
	}
}

func TestBuildMultipartStream_EarlyCloseNoLeak(t *testing.T) {
	g0 := runtime.NumGoroutine()
	er := &errReader{r: bytes.NewReader(bytes.Repeat([]byte{1}, 4<<20)), failAt: 1 << 30}
	body, _, _, _ := buildMultipartStream(er, "f", false, -1)
	buf := make([]byte, 64)
	_, _ = body.Read(buf)
	_ = body.Close()
	for i := 0; i < 50; i++ { // settle
		if runtime.NumGoroutine() <= g0+2 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("goroutine leak: %d → %d", g0, runtime.NumGoroutine())
}

// TestBuildMultipartStream_SmallPath_Roundtrip verifies that the small-file
// path (hint < multipartPipeBufSize, currently 4 MiB) produces a well-formed
// multipart body with correct payload.
func TestBuildMultipartStream_SmallPath_Roundtrip(t *testing.T) {
	payload := bytes.Repeat([]byte{0xCD}, 512<<10) // 512 KiB — well below multipartPipeBufSize (4 MiB)
	src := io.NopCloser(bytes.NewReader(payload))
	body, ct, _, err := buildMultipartStream(src, "small.bin", false, int64(len(payload)))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = body.Close() }()

	mt, params, err := mime.ParseMediaType(ct)
	if err != nil || mt != "multipart/form-data" {
		t.Fatalf("ct=%q err=%v", ct, err)
	}
	mr := multipart.NewReader(body, params["boundary"])
	part, err := mr.NextPart()
	if err != nil {
		t.Fatal(err)
	}
	if part.FormName() != multipartFieldContent || part.FileName() != "small.bin" {
		t.Fatalf("name=%q file=%q", part.FormName(), part.FileName())
	}
	got := sha256.New()
	if _, err := io.Copy(got, part); err != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256(payload)
	if !bytes.Equal(got.Sum(nil), want[:]) {
		t.Fatal("payload digest mismatch")
	}
	if _, err := mr.NextPart(); err != io.EOF {
		t.Fatalf("expected EOF, got %v", err)
	}
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
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = body.Close() }()
			if contentLength <= 0 {
				t.Fatalf("expected positive contentLength, got %d", contentLength)
			}
			if er.closeCnt == 0 {
				t.Fatal("expected src.Close to be called synchronously")
			}
			mt, params, err := mime.ParseMediaType(ct)
			if err != nil || mt != "multipart/form-data" {
				t.Fatalf("ct=%q err=%v", ct, err)
			}
			// Drain into a buffer so we can both verify wire size and parse
			// (boundary is per-call, so a second buildMultipartStream() would
			// have a different boundary than the ct we captured here).
			var captured bytes.Buffer
			n, err := captured.ReadFrom(body)
			if err != nil {
				t.Fatal(err)
			}
			if n != contentLength {
				t.Fatalf("wire size %d != contentLength %d", n, contentLength)
			}
			mr := multipart.NewReader(&captured, params["boundary"])
			part, err := mr.NextPart()
			if err != nil {
				t.Fatal(err)
			}
			if part.FormName() != multipartFieldContent || part.FileName() != "f.bin" {
				t.Fatalf("name=%q file=%q", part.FormName(), part.FileName())
			}
			got := sha256.New()
			if _, err := io.Copy(got, part); err != nil {
				t.Fatal(err)
			}
			want := sha256.Sum256(payload)
			if !bytes.Equal(got.Sum(nil), want[:]) {
				t.Fatal("payload digest mismatch")
			}
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
	if err == nil {
		t.Fatal("expected close error to propagate, got nil")
	}
	if !strings.Contains(err.Error(), "synthetic-close-fail") {
		t.Fatalf("expected synthetic-close-fail, got %v", err)
	}
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
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = body.Close() }()
			if contentLength <= 0 {
				t.Fatalf("expected positive contentLength, got %d", contentLength)
			}
			n, err := io.Copy(io.Discard, body)
			if err != nil {
				t.Fatal(err)
			}
			if n != contentLength {
				t.Fatalf("wire size %d != precomputed contentLength %d", n, contentLength)
			}
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
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = body.Close() }()
			if contentLength != -1 {
				t.Fatalf("expected contentLength=-1, got %d", contentLength)
			}
		})
	}
}

// TestBuildMultipartStream_SmallPath_Recursive verifies the small-file path
// emits the "name" field when isRecursive=true.
func TestBuildMultipartStream_SmallPath_Recursive(t *testing.T) {
	payload := []byte("small-zip-data")
	src := io.NopCloser(bytes.NewReader(payload))
	body, ct, _, err := buildMultipartStream(src, "arch.zip", true, int64(len(payload)))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = body.Close() }()

	_, params, _ := mime.ParseMediaType(ct)
	mr := multipart.NewReader(body, params["boundary"])
	sawName := false
	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if part.FormName() == multipartFieldName {
			data, _ := io.ReadAll(part)
			if string(data) != "arch.zip" {
				t.Fatalf("name=%q", data)
			}
			sawName = true
		}
	}
	if !sawName {
		t.Fatal("expected name field for recursive small upload")
	}
}
