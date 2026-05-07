# File streaming PR 1 — Upload + bench infrastructure

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the upload path's buffered payload handling (`readFileAs []byte` → `createMultipartBody bytes.Buffer`) with an `io.Reader` pipeline so peak memory at 100 MB is < 50 MiB RSS, while preserving all existing functional behavior (privilege demotion, archive, `useBlob`, multipart, timeouts, ctx cancellation).

**Architecture:** Bench-first flow. Land bench/RSS infrastructure and capture a baseline before any code change, then introduce two helpers (`cmdReadCloser` for demoted reads, `buildMultipartStream` for streaming multipart via `io.Pipe`+goroutine), then flip all upload-touching signatures to `io.Reader` in one cohesive change so the build stays green. Verify the acceptance gate from the spec at the end with `benchstat` and `/usr/bin/time`.

**Tech Stack:** Go (existing toolchain), `testing` + `-benchmem`, `golang.org/x/perf/cmd/benchstat`, `/usr/bin/time -l` (macOS dev) / `-v` (Linux production), `net/http`/`httptest`, `mime/multipart`, `os/exec`.

**Spec:** `docs/superpowers/specs/2026-05-07-file-streaming-design.md`

---

## Task 1: Bench helpers + baseline benchmarks (still calling current buffered code)

**Files:**
- Create: `pkg/executor/handlers/file/bench_test.go`

- [ ] **Step 1: Write `bench_test.go` with helpers and baseline benchmarks**

```go
package file

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// benchSizes covers the same payload range as issue #199.
var benchSizes = []int{1 << 20, 10 << 20, 100 << 20}

// makeTempFile writes `size` bytes of pseudo-random content into a temp file
// and returns the path. b.Cleanup removes it. Random content prevents
// compression-related throughput inflation in transports.
func makeTempFile(b *testing.B, size int) string {
	b.Helper()
	f, err := os.CreateTemp(b.TempDir(), "bench-*.bin")
	if err != nil {
		b.Fatalf("CreateTemp: %v", err)
	}
	defer f.Close()
	if _, err := io.CopyN(f, rand.Reader, int64(size)); err != nil {
		b.Fatalf("CopyN: %v", err)
	}
	return f.Name()
}

// newSinkServer returns an httptest server that drains the request body and
// returns 200. Useful for upload-path benchmarks: the payload travels over
// loopback HTTP and is discarded server-side.
func newSinkServer(b *testing.B) *httptest.Server {
	b.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	b.Cleanup(srv.Close)
	return srv
}

// reportGC records GC count and total pause delta as bench-only metrics.
func reportGC(b *testing.B, before, after runtime.MemStats) {
	b.Helper()
	b.ReportMetric(float64(after.NumGC-before.NumGC)/float64(b.N), "gc-count/op")
	b.ReportMetric(float64(after.PauseTotalNs-before.PauseTotalNs)/float64(b.N), "gc-pause-ns/op")
}

// BenchmarkCreateMultipartBodyLargePayload preserves the name from issue #199
// so before/after benchstat tables compare 1:1.
func BenchmarkCreateMultipartBodyLargePayload(b *testing.B) {
	for _, size := range benchSizes {
		b.Run(fmt.Sprintf("%dMB", size>>20), func(b *testing.B) {
			payload := make([]byte, size)
			if _, err := io.ReadFull(rand.Reader, payload); err != nil {
				b.Fatal(err)
			}
			h := &FileHandler{}
			b.SetBytes(int64(size))
			b.ReportAllocs()
			var ms0, ms1 runtime.MemStats
			runtime.GC()
			runtime.ReadMemStats(&ms0)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				body, _, err := h.createMultipartBody(payload, "f.bin", false, false)
				if err != nil {
					b.Fatal(err)
				}
				if _, err := io.Copy(io.Discard, &body); err != nil {
					b.Fatal(err)
				}
			}
			b.StopTimer()
			runtime.ReadMemStats(&ms1)
			reportGC(b, ms0, ms1)
		})
	}
}

// BenchmarkUpload_E2E_Local exercises the full upload composition that the
// handler will use after the streaming refactor. It is defined now (against
// current buffered code) so we capture a baseline; later commits replace
// internals while the benchmark name stays identical.
func BenchmarkUpload_E2E_Local(b *testing.B) {
	for _, size := range benchSizes {
		b.Run(fmt.Sprintf("%dMB", size>>20), func(b *testing.B) {
			path := makeTempFile(b, size)
			srv := newSinkServer(b)
			h := &FileHandler{}
			b.SetBytes(int64(size))
			b.ReportAllocs()
			var ms0, ms1 runtime.MemStats
			runtime.GC()
			runtime.ReadMemStats(&ms0)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				data, err := os.ReadFile(path)
				if err != nil {
					b.Fatal(err)
				}
				body, ct, err := h.createMultipartBody(data, filepath.Base(path), false, false)
				if err != nil {
					b.Fatal(err)
				}
				req, err := http.NewRequest(http.MethodPost, srv.URL, &body)
				if err != nil {
					b.Fatal(err)
				}
				req.Header.Set("Content-Type", ct)
				resp, err := http.DefaultClient.Do(req)
				if err != nil {
					b.Fatal(err)
				}
				_, _ = io.Copy(io.Discard, resp.Body)
				_ = resp.Body.Close()
			}
			b.StopTimer()
			runtime.ReadMemStats(&ms1)
			reportGC(b, ms0, ms1)
		})
	}
	_ = bytes.NewReader // keep import lest goimports drop it later
}
```

- [ ] **Step 2: Run the benchmarks once to make sure they compile and execute**

Run:
```
go test -run=^$ -bench=BenchmarkCreateMultipartBodyLargePayload/1MB -benchtime=1x -benchmem ./pkg/executor/handlers/file/
```
Expected: PASS, output includes `B/op` and `allocs/op` columns.

- [ ] **Step 3: Capture the upload baseline at -count=5**

Run:
```
go test -run=^$ -bench='BenchmarkCreateMultipartBodyLargePayload|BenchmarkUpload_E2E_Local' -count=5 -benchmem ./pkg/executor/handlers/file/ | tee /tmp/pr1-upload-old.txt
mkdir -p docs/superpowers/baselines
cp /tmp/pr1-upload-old.txt docs/superpowers/baselines/2026-05-07-pr1-upload-baseline.txt
```
Expected: file written, contains 100MB lines like `BenchmarkCreateMultipartBodyLargePayload/100MB-N    ... B/op ... allocs/op` with `B/op` ≥ ~100 MB (current buffered behavior).

- [ ] **Step 4: Commit**

```
git add pkg/executor/handlers/file/bench_test.go docs/superpowers/baselines/2026-05-07-pr1-upload-baseline.txt
git commit -m "test: add upload bench harness and capture buffered baseline (#199)"
```

---

## Task 2: Makefile `bench-mem` target + RSS baseline

**Files:**
- Modify: `Makefile` (create if absent)

- [ ] **Step 1: Append `bench-mem` target**

```makefile
TIME      ?= $(shell command -v gtime 2>/dev/null || command -v /usr/bin/time)
TIME_FLAG ?= $(shell [ "$$(uname)" = "Darwin" ] && echo -l || echo -v)

.PHONY: bench-mem
bench-mem:
	go test -c -o /tmp/file_bench ./pkg/executor/handlers/file/
	@for sz in 1MB 10MB 100MB; do \
		echo "==== upload $$sz ===="; \
		$(TIME) $(TIME_FLAG) /tmp/file_bench -test.bench=BenchmarkUpload_E2E_Local/$$sz -test.benchmem -test.benchtime=1x 2>&1 | tail -25; \
	done
```

- [ ] **Step 2: Run the target and verify RSS is reported**

Run: `make bench-mem`
Expected: each block prints either `maximum resident set size` (macOS `-l`) or `Maximum resident set size` (Linux `-v`). 100MB block shows ≥ 400 MiB matching issue #199 baseline.

- [ ] **Step 3: Save RSS baseline to file**

Run:
```
make bench-mem 2>&1 | tee docs/superpowers/baselines/2026-05-07-pr1-upload-rss-baseline.txt
```

- [ ] **Step 4: Commit**

```
git add Makefile docs/superpowers/baselines/2026-05-07-pr1-upload-rss-baseline.txt
git commit -m "build: add bench-mem make target for RSS measurement (#199)"
```

---

## Task 3: CI workflow for nightly bench

**Files:**
- Create: `.github/workflows/bench.yml`

- [ ] **Step 1: Write workflow**

```yaml
name: bench

on:
  schedule:
    - cron: '0 18 * * *'
  workflow_dispatch: {}

jobs:
  bench:
    runs-on: ubuntu-latest
    timeout-minutes: 30
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version-file: go.mod
      - name: Run benchmarks
        run: |
          go test -bench=. -benchmem -count=5 -run=^$ -timeout=20m \
            ./pkg/executor/handlers/file/ | tee bench.txt
      - uses: actions/upload-artifact@v4
        with:
          name: bench-results
          path: bench.txt
          retention-days: 30
```

- [ ] **Step 2: Validate YAML locally**

Run: `python -c "import yaml,sys; yaml.safe_load(open('.github/workflows/bench.yml'))"`
Expected: no output, exit 0.

- [ ] **Step 3: Commit**

```
git add .github/workflows/bench.yml
git commit -m "ci: add nightly bench workflow for upload/download measurements (#199)"
```

---

## Task 4: `cmdReadCloser` helper (TDD)

**Files:**
- Create: `pkg/executor/handlers/file/cmd_reader_unix.go`
- Create: `pkg/executor/handlers/file/cmd_reader_windows.go`
- Create: `pkg/executor/handlers/file/cmd_reader_unix_test.go`

- [ ] **Step 1: Write failing tests**

```go
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test -run TestCmdReadCloser ./pkg/executor/handlers/file/`
Expected: FAIL with `undefined: newCmdReadCloser`.

- [ ] **Step 3: Implement `cmd_reader_unix.go`**

```go
//go:build !windows

package file

import (
	"bytes"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"sync/atomic"
)

type cmdReadCloser struct {
	cmd    *exec.Cmd
	stdout io.ReadCloser
	stderr *bytes.Buffer
	closed atomic.Bool
}

func newCmdReadCloser(cmd *exec.Cmd) (*cmdReadCloser, error) {
	var errBuf bytes.Buffer
	cmd.Stderr = &errBuf
	out, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return &cmdReadCloser{cmd: cmd, stdout: out, stderr: &errBuf}, nil
}

func (r *cmdReadCloser) Read(p []byte) (int, error) { return r.stdout.Read(p) }

func (r *cmdReadCloser) Close() error {
	if !r.closed.CompareAndSwap(false, true) {
		return nil
	}
	_ = r.stdout.Close()
	if werr := r.cmd.Wait(); werr != nil {
		msg := strings.TrimSpace(r.stderr.String())
		if msg == "" {
			return werr
		}
		return fmt.Errorf("%w: %s", werr, msg)
	}
	return nil
}
```

- [ ] **Step 4: Implement Windows stub**

```go
//go:build windows

package file

// cmdReadCloser is unix-only; this stub keeps the package buildable on
// Windows where readFileAs uses os.Open directly.
```

- [ ] **Step 5: Run tests to verify pass**

Run: `go test -run TestCmdReadCloser ./pkg/executor/handlers/file/`
Expected: PASS.

- [ ] **Step 6: Commit**

```
git add pkg/executor/handlers/file/cmd_reader_unix.go pkg/executor/handlers/file/cmd_reader_windows.go pkg/executor/handlers/file/cmd_reader_unix_test.go
git commit -m "feat(file): add cmdReadCloser helper for streaming demoted reads (#199)"
```

---

## Task 5: `buildMultipartStream` helper (TDD)

**Files:**
- Create: `pkg/executor/handlers/file/multipart_stream.go`
- Create: `pkg/executor/handlers/file/multipart_stream_test.go`

- [ ] **Step 1: Write failing tests**

```go
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
	body, ct, err := buildMultipartStream(src, "f.bin", false)
	if err != nil {
		t.Fatal(err)
	}
	defer body.Close()
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
	body, ct, err := buildMultipartStream(src, "tree.zip", true)
	if err != nil {
		t.Fatal(err)
	}
	defer body.Close()
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
	body, _, err := buildMultipartStream(er, "f", false)
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
	body, _, _ := buildMultipartStream(er, "f", false)
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test -run TestBuildMultipartStream ./pkg/executor/handlers/file/`
Expected: FAIL with `undefined: buildMultipartStream`.

- [ ] **Step 3: Implement `multipart_stream.go`**

```go
package file

import (
	"fmt"
	"io"
	"mime/multipart"
)

// buildMultipartStream returns a streaming multipart body containing `src`
// under form field "content". The caller MUST Close the returned reader. The
// goroutine owns src.Close so leaking the reader does not leak the source.
func buildMultipartStream(src io.ReadCloser, fileName string, isRecursive bool) (io.ReadCloser, string, error) {
	pr, pw := io.Pipe()
	mw := multipart.NewWriter(pw)
	contentType := mw.FormDataContentType()

	go func() {
		defer src.Close()
		defer func() {
			if rec := recover(); rec != nil {
				_ = pw.CloseWithError(fmt.Errorf("multipart panic: %v", rec))
			}
		}()
		fw, err := mw.CreateFormFile("content", fileName)
		if err != nil {
			_ = pw.CloseWithError(err)
			return
		}
		if _, err := io.Copy(fw, src); err != nil {
			_ = pw.CloseWithError(err)
			return
		}
		if isRecursive {
			if err := mw.WriteField("name", fileName); err != nil {
				_ = pw.CloseWithError(err)
				return
			}
		}
		if err := mw.Close(); err != nil {
			_ = pw.CloseWithError(err)
			return
		}
		_ = pw.Close()
	}()

	return pr, contentType, nil
}
```

- [ ] **Step 4: Run tests to verify pass**

Run: `go test -run TestBuildMultipartStream ./pkg/executor/handlers/file/`
Expected: PASS (4 tests).

- [ ] **Step 5: Commit**

```
git add pkg/executor/handlers/file/multipart_stream.go pkg/executor/handlers/file/multipart_stream_test.go
git commit -m "feat(file): add buildMultipartStream for streaming upload bodies (#199)"
```

---

## Task 6: Flip signatures and switch handleUpload to streaming

This task changes 7 files in lockstep because they form a single compile unit. Tests are updated first to express the new behavior, then the implementation switches over in one commit so the build never breaks.

**Files:**
- Modify: `pkg/utils/http_client.go`
- Modify: `pkg/scheduler/session.go`
- Modify: `pkg/executor/handlers/common/interfaces.go`
- Modify: `pkg/executor/handlers/file/file_io_unix.go` (`readFileAs` only)
- Modify: `pkg/executor/handlers/file/file_io_windows.go` (`readFileAs` only)
- Modify: `pkg/executor/handlers/file/file.go` (`handleUpload`, `fileUpload`, remove `createMultipartBody`)
- Modify: `pkg/executor/handlers/file/file_test.go` (upload tests + bench)

- [ ] **Step 1: Update `bench_test.go` to call streaming entrypoints**

Replace `BenchmarkUpload_E2E_Local` body so it consumes `readFileAs` + `buildMultipartStream` instead of `os.ReadFile` + `createMultipartBody`. Keep the function name and `b.SetBytes` value identical so benchstat aligns.

```go
func BenchmarkUpload_E2E_Local(b *testing.B) {
	for _, size := range benchSizes {
		b.Run(fmt.Sprintf("%dMB", size>>20), func(b *testing.B) {
			path := makeTempFile(b, size)
			srv := newSinkServer(b)
			b.SetBytes(int64(size))
			b.ReportAllocs()
			var ms0, ms1 runtime.MemStats
			runtime.GC()
			runtime.ReadMemStats(&ms0)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				src, _, err := readFileAs(context.Background(), path, nil)
				if err != nil {
					b.Fatal(err)
				}
				body, ct, err := buildMultipartStream(src, filepath.Base(path), false)
				if err != nil {
					_ = src.Close()
					b.Fatal(err)
				}
				req, _ := http.NewRequest(http.MethodPost, srv.URL, body)
				req.Header.Set("Content-Type", ct)
				resp, err := http.DefaultClient.Do(req)
				if err != nil {
					_ = body.Close()
					b.Fatal(err)
				}
				_, _ = io.Copy(io.Discard, resp.Body)
				_ = resp.Body.Close()
				_ = body.Close()
			}
			b.StopTimer()
			runtime.ReadMemStats(&ms1)
			reportGC(b, ms0, ms1)
		})
	}
}
```

Also update `BenchmarkCreateMultipartBodyLargePayload` to call `buildMultipartStream` against a `bytes.NewReader(payload)` source. The exported name stays the same to keep benchstat tables aligned with Task 1's baseline:

```go
func BenchmarkCreateMultipartBodyLargePayload(b *testing.B) {
	for _, size := range benchSizes {
		b.Run(fmt.Sprintf("%dMB", size>>20), func(b *testing.B) {
			payload := make([]byte, size)
			if _, err := io.ReadFull(rand.Reader, payload); err != nil {
				b.Fatal(err)
			}
			b.SetBytes(int64(size))
			b.ReportAllocs()
			var ms0, ms1 runtime.MemStats
			runtime.GC()
			runtime.ReadMemStats(&ms0)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				src := io.NopCloser(bytes.NewReader(payload))
				body, _, err := buildMultipartStream(src, "f.bin", false)
				if err != nil {
					b.Fatal(err)
				}
				if _, err := io.Copy(io.Discard, body); err != nil {
					b.Fatal(err)
				}
				_ = body.Close()
			}
			b.StopTimer()
			runtime.ReadMemStats(&ms1)
			reportGC(b, ms0, ms1)
		})
	}
}
```

(Add `"context"` to the import block.)

- [ ] **Step 2: Update `pkg/utils/http_client.go`**

Replace `Put`:

```go
func Put(url string, body io.Reader, contentLength int64, timeout time.Duration) ([]byte, int, error) {
	req, err := http.NewRequest(http.MethodPut, url, body) // lgtm[go/request-forgery]
	if err != nil {
		return nil, 0, err
	}
	if contentLength >= 0 {
		req.ContentLength = contentLength
	}
	client := NewHTTPClient()
	client.Timeout = timeout
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, err
	}
	return respBody, resp.StatusCode, nil
}
```

Drop the `bytes` import if no longer used.

- [ ] **Step 3: Update `pkg/executor/handlers/common/interfaces.go`**

```go
type APISession interface {
	MultipartRequest(url string, body io.Reader, contentType string, timeout time.Duration) ([]byte, int, error)
}
```

Update the import block (`bytes` → `io` if needed; keep both if other declarations still use `bytes`).

- [ ] **Step 4: Update `pkg/scheduler/session.go::MultipartRequest`**

```go
func (session *Session) MultipartRequest(url string, body io.Reader, contentType string, timeout time.Duration) ([]byte, int, error) {
	req, err := http.NewRequest(http.MethodPost, url, body)
	if err != nil {
		return nil, 0, err
	}
	ctx, cancel := context.WithTimeout(req.Context(), timeout*time.Second)
	defer cancel()
	req = req.WithContext(ctx)
	req.Header.Set("Authorization", session.Authorization)
	req.Header.Set("User-Agent", utils.GetUserAgent("alpamon"))
	req.Header.Set("Content-Type", contentType)
	resp, err := session.Client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, err
	}
	return responseBody, resp.StatusCode, nil
}
```

- [ ] **Step 5: Update `pkg/executor/handlers/file/file_io_unix.go::readFileAs`**

```go
func readFileAs(ctx context.Context, path string, sysProcAttr *syscall.SysProcAttr) (io.ReadCloser, int64, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, 0, err
	}
	size := st.Size()
	if sysProcAttr == nil {
		f, err := os.Open(path)
		if err != nil {
			return nil, 0, err
		}
		return f, size, nil
	}
	cmd := exec.CommandContext(ctx, "cat", path)
	cmd.SysProcAttr = sysProcAttr
	rc, err := newCmdReadCloser(cmd)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to start cat: %w", err)
	}
	return rc, size, nil
}
```

(Leave `writeFileAs` untouched; it stays on the `[]byte` signature for now — PR 2 will migrate it.)

- [ ] **Step 6: Update `pkg/executor/handlers/file/file_io_windows.go::readFileAs`**

```go
func readFileAs(ctx context.Context, path string, sysProcAttr *syscall.SysProcAttr) (io.ReadCloser, int64, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, 0, err
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, 0, err
	}
	return f, st.Size(), nil
}
```

(Leave `writeFileAs` untouched.)

- [ ] **Step 7: Update `pkg/executor/handlers/file/file.go::handleUpload` and `fileUpload`**

Remove `createMultipartBody` entirely. Rewrite `handleUpload` to thread readers, and rewrite `fileUpload` to take a `body io.Reader` plus contentLength:

```go
func (h *FileHandler) handleUpload(ctx context.Context, args *common.CommandArgs) (int, string) {
	log.Debug().
		Str("username", args.Username).
		Str("groupname", args.Groupname).
		Int("pathCount", len(args.Paths)).
		Msg("Uploading files")

	if len(args.Paths) == 0 {
		return 1, "No paths provided"
	}

	sysProcAttr, homeDirectory, err := h.demoteWithHomeDir(args.Username, args.Groupname, false, args.HomeDirectory)
	if err != nil {
		log.Error().Err(err).Msg("Failed to demote user.")
		return 1, err.Error()
	}

	paths, bulk, recursive, err := h.parsePaths(homeDirectory, args.Paths)
	if err != nil {
		log.Error().Err(err).Msg("Failed to parse paths")
		return 1, err.Error()
	}

	name, cleanupPath, err := h.makeArchive(ctx, paths, bulk, recursive, sysProcAttr)
	if err != nil {
		log.Error().Err(err).Msg("Failed to create archive")
		return 1, err.Error()
	}
	if cleanupPath != "" {
		defer func() { _ = os.Remove(cleanupPath) }()
	}

	src, size, err := readFileAs(ctx, name, sysProcAttr)
	if err != nil {
		log.Error().Err(err).Msg("Failed to read file for upload.")
		return 1, err.Error()
	}
	defer func() { _ = src.Close() }()

	statusCode, err := h.fileUpload(ctx, args, src, size, filepath.Base(name), recursive)
	if err != nil {
		log.Error().Err(err).Msg("Failed to upload file")
		return 1, err.Error()
	}
	if statusCode == http.StatusOK {
		return 0, fmt.Sprintf("Successfully uploaded %d file(s).", len(paths))
	}
	return 1, "You do not have permission to read on the directory. or directory does not exist"
}

func (h *FileHandler) fileUpload(_ context.Context, args *common.CommandArgs, src io.ReadCloser, size int64, fileName string, recursive bool) (int, error) {
	if args.UseBlob {
		_, code, err := utils.Put(args.Content, src, size, 0)
		return code, err
	}
	if h.apiSession == nil {
		return 0, errors.New("API session not available")
	}
	body, contentType, err := buildMultipartStream(src, fileName, recursive)
	if err != nil {
		return 0, err
	}
	defer func() { _ = body.Close() }()
	_, code, err := h.apiSession.MultipartRequest(args.Content, body, contentType, time.Duration(fileUploadTimeout)*time.Second)
	return code, err
}
```

`buildMultipartStream` takes ownership of `src.Close()` once handed in. The `defer src.Close()` in `handleUpload` covers the error/`useBlob` paths; in the multipart path the goroutine closes `src` and the deferred call becomes a no-op (because `os.File.Close` and `cmdReadCloser.Close` are idempotent — verify Task 4 covers `cmdReadCloser`; `os.File.Close` is idempotent per stdlib).

> **Caveat:** `*os.File.Close` returns `os.ErrClosed` on second call. To keep idempotent semantics, wrap `src` in a `closeOnce` adapter before passing to `buildMultipartStream`. Add the helper at the bottom of `file.go`:
>
> ```go
> type closeOnceReader struct {
>     io.ReadCloser
>     once sync.Once
>     err  error
> }
>
> func (c *closeOnceReader) Close() error {
>     c.once.Do(func() { c.err = c.ReadCloser.Close() })
>     return c.err
> }
> ```
> and in `handleUpload` wrap `src = &closeOnceReader{ReadCloser: src}` before the deferred close. Add `"sync"` to imports.

- [ ] **Step 8: Update existing upload tests in `file_test.go`**

Find tests that pass `bytes.Buffer` to `fileUpload` or assert on `createMultipartBody`. Replace mock expectations to consume `io.Reader` for the multipart body. Re-run.

(Concrete test names depend on what already exists. The implementer should `grep -n "createMultipartBody\|MultipartRequest\|fileUpload" pkg/executor/handlers/file/file_test.go` and migrate each one. Mocks of `APISession.MultipartRequest` accept `io.Reader` now; capture the body via `io.ReadAll(body)` for assertions.)

- [ ] **Step 9: Build and run all tests**

Run: `go build ./... && go test -v ./... -p 1 -count=1`
Expected: PASS for everything; if a test outside `file/` fails because of the interface change, it is on a mock that captured the old signature — update those mocks.

- [ ] **Step 10: Commit**

```
git add pkg/utils/http_client.go pkg/scheduler/session.go pkg/executor/handlers/common/interfaces.go pkg/executor/handlers/file/file_io_unix.go pkg/executor/handlers/file/file_io_windows.go pkg/executor/handlers/file/file.go pkg/executor/handlers/file/file_test.go pkg/executor/handlers/file/bench_test.go
git commit -m "feat(file): stream upload path end-to-end (#199)

readFileAs/utils.Put/APISession.MultipartRequest now accept io.Reader.
handleUpload threads the reader from readFileAs through
buildMultipartStream into the HTTP transport, eliminating the per-payload
bytes.Buffer that drove memory peak."
```

---

## Task 7: After-measurement, benchstat, acceptance gate, PR open

**Files:**
- Create: `docs/superpowers/baselines/2026-05-07-pr1-upload-results.md`

- [ ] **Step 1: Capture after-bench results**

Run:
```
go test -run=^$ -bench='BenchmarkCreateMultipartBodyLargePayload|BenchmarkUpload_E2E_Local' -count=5 -benchmem ./pkg/executor/handlers/file/ | tee /tmp/pr1-upload-new.txt
```
Expected: file written with same benchmark names, `B/op` for `100MB` ≪ baseline (target < 10 MB).

- [ ] **Step 2: Run benchstat**

Install if missing: `go install golang.org/x/perf/cmd/benchstat@latest`
Run:
```
benchstat /tmp/pr1-upload-old.txt /tmp/pr1-upload-new.txt | tee /tmp/pr1-upload-stat.txt
```
Expected: `100MB` rows show negative `B/op` and `allocs/op` deltas, `ns/op` delta within ±10%.

- [ ] **Step 3: Capture after-RSS**

Run:
```
make bench-mem 2>&1 | tee /tmp/pr1-upload-rss-new.txt
```
Expected: `maximum resident set size` at 100MB block < 50 MiB (52,428,800 bytes).

- [ ] **Step 4: Verify acceptance gate**

Read `/tmp/pr1-upload-new.txt` and `/tmp/pr1-upload-rss-new.txt`. Confirm:
- 100MB `B/op` < 10,000,000
- 100MB `allocs/op` < 50
- 100MB `ns/op` regression vs baseline ≤ +10% (use benchstat output)
- 100MB RSS < 52,428,800

If any gate fails, STOP and investigate before proceeding to PR creation. Likely culprits: missing `b.ResetTimer()`, wrong-size buffer in `io.Copy` somewhere, hidden `io.ReadAll` in updated tests.

- [ ] **Step 5: Write results doc**

```markdown
# PR 1 (upload streaming) — measurement results

## Bench (benchstat -count=5)
<paste /tmp/pr1-upload-stat.txt>

## RSS (/usr/bin/time)
- baseline (Task 2): <100MB RSS from 2026-05-07-pr1-upload-rss-baseline.txt>
- after  (Task 7):  <100MB RSS from /tmp/pr1-upload-rss-new.txt>

## Acceptance gate
| Metric (100MB) | Target  | Result | Pass |
|---|---|---|---|
| B/op           | < 10 MB | <fill> | ✅/❌ |
| allocs/op      | < 50    | <fill> | ✅/❌ |
| ns/op delta    | ≤ +10%  | <fill> | ✅/❌ |
| RSS            | < 50 MiB| <fill> | ✅/❌ |
```

Save to `docs/superpowers/baselines/2026-05-07-pr1-upload-results.md`.

- [ ] **Step 6: Commit results doc**

```
git add docs/superpowers/baselines/2026-05-07-pr1-upload-results.md
git commit -m "docs: PR 1 upload streaming — bench and RSS results (#199)"
```

- [ ] **Step 7: Open PR**

```
git push -u origin 199-fix-memory-peak
gh pr create --base main --title "feat(file): stream upload path + bench infrastructure (#199)" --body "$(cat <<'EOF'
## Summary
- Replace buffered upload payload handling (`readFileAs []byte` → `createMultipartBody bytes.Buffer`) with an `io.Reader` pipeline.
- Add `cmdReadCloser` and `buildMultipartStream` helpers for streaming demoted reads and multipart body composition.
- Flip `utils.Put`, `APISession.MultipartRequest`, and `readFileAs` signatures to accept `io.Reader`.
- Add bench harness, RSS measurement Make target, and nightly bench CI workflow.

Spec: `docs/superpowers/specs/2026-05-07-file-streaming-design.md`
Plan: `docs/superpowers/plans/2026-05-07-file-streaming-pr1-upload.md`
Closes part of #199 (upload path).

## Measurements
See `docs/superpowers/baselines/2026-05-07-pr1-upload-results.md` for full benchstat and RSS deltas.

## Test plan
- [x] `go test -v ./... -p 1 -count=1`
- [x] `go test -bench=. -benchmem -count=5 ./pkg/executor/handlers/file/`
- [x] `make bench-mem`
- [x] Acceptance gate (B/op, allocs/op, ns/op, RSS) all pass
EOF
)"
```

Expected: PR URL printed.

---

## Self-review notes (writer)

- **Spec coverage:** every change in spec PR 1 file table is covered (cmd_reader_unix.go Task 4, multipart_stream.go Task 5, file_io_unix.go/file_io_windows.go/file.go/utils/http_client.go/scheduler/session.go/common/interfaces.go Task 6, bench_test.go Task 1+6, Makefile Task 2, .github/workflows/bench.yml Task 3). Acceptance gate verified in Task 7.
- **Placeholders:** none. The closeOnceReader caveat in Task 6 Step 7 is fully spelled out.
- **Type consistency:** `readFileAs` → `(io.ReadCloser, int64, error)` is consistent in Tasks 5 (helper consumer), 6 (impl + handler), and 7 (bench update). `MultipartRequest(io.Reader)` is consistent across interfaces.go, session.go, and the file handler. `Put(url, body io.Reader, contentLength int64, timeout)` is consistent.
- **Bench-first:** Tasks 1–3 land bench infra and capture baseline before any production-code change. Task 6 is the first compile-affecting change, after helpers exist.
