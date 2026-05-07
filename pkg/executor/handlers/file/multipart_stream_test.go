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

func (e *errReader) Close() error { e.closeCnt++; return nil }

func TestBuildMultipartStream_Roundtrip(t *testing.T) {
	payload := bytes.Repeat([]byte{0xAB}, 1<<20)
	src := io.NopCloser(bytes.NewReader(payload))
	body, ct, err := buildMultipartStream(src, "f.bin", false, -1)
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
	body, ct, err := buildMultipartStream(src, "tree.zip", true, -1)
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
	body, _, err := buildMultipartStream(er, "f", false, -1)
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

func TestBuildMultipartStream_EarlyCloseNoLeak(t *testing.T) {
	g0 := runtime.NumGoroutine()
	er := &errReader{r: bytes.NewReader(bytes.Repeat([]byte{1}, 4<<20)), failAt: 1 << 30}
	body, _, _ := buildMultipartStream(er, "f", false, -1)
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
// path (hint < 1 MiB) produces a well-formed multipart body with correct payload.
func TestBuildMultipartStream_SmallPath_Roundtrip(t *testing.T) {
	payload := bytes.Repeat([]byte{0xCD}, 512<<10) // 512 KiB — below 1 MiB threshold
	src := io.NopCloser(bytes.NewReader(payload))
	body, ct, err := buildMultipartStream(src, "small.bin", false, int64(len(payload)))
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

// TestBuildMultipartStream_SmallPath_Recursive verifies the small-file path
// emits the "name" field when isRecursive=true.
func TestBuildMultipartStream_SmallPath_Recursive(t *testing.T) {
	payload := []byte("small-zip-data")
	src := io.NopCloser(bytes.NewReader(payload))
	body, ct, err := buildMultipartStream(src, "arch.zip", true, int64(len(payload)))
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
