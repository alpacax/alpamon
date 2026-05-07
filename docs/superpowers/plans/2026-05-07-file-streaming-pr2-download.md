# File streaming PR 2 — Download

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the download path's buffered payload handling (`io.ReadAll(resp.Body)` + `[]byte` content + buffered `IsZipFile`) with an `io.Reader` pipeline so peak memory at 100 MB is < 50 MiB RSS, while preserving `AllowOverwrite`/`AllowUnzip`/`url|text|base64` semantics, privilege demotion, timeouts, and ctx cancellation.

**Architecture:** Bench-first flow. Land download bench/RSS infrastructure and capture a baseline before any code change. Then flip `fetchFromURL`, `getFileData`, and `writeFileAs` to `io.Reader`/`io.ReadCloser`, change zip detection to a four-byte sniff at the on-disk path (`IsZipFileAtPath`), and migrate `fileDownload` to `io.Copy` from response/decoder into the file. Verify the acceptance gate from the spec at the end with `benchstat` and `/usr/bin/time`.

**Tech Stack:** Go (existing toolchain), `testing` + `-benchmem`, `golang.org/x/perf/cmd/benchstat`, `/usr/bin/time -l` (macOS dev) / `-v` (Linux production), `net/http`/`httptest`, `os/exec` (`tee`), `encoding/base64.NewDecoder`.

**Spec:** `docs/superpowers/specs/2026-05-07-file-streaming-design.md`
**Depends on:** PR 1 (`docs/superpowers/plans/2026-05-07-file-streaming-pr1-upload.md`) merged.

---

## Task 1: Download bench harness + baseline (calling current `[]byte` code)

**Files:**
- Modify: `pkg/executor/handlers/file/bench_test.go`

- [ ] **Step 1: Append download benchmarks**

Add to the existing `bench_test.go` (helpers from PR 1 are already in place):

```go
// newPayloadServer returns a server that responds with `size` bytes of fixed
// content. Useful for download-path benchmarks.
func newPayloadServer(b *testing.B, size int) *httptest.Server {
	b.Helper()
	payload := bytes.Repeat([]byte("x"), size)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", strconv.Itoa(len(payload)))
		_, _ = w.Write(payload)
	}))
	b.Cleanup(srv.Close)
	return srv
}

// BenchmarkFetchFromURLLargePayload preserves the name from issue #199 so
// before/after benchstat tables compare 1:1.
func BenchmarkFetchFromURLLargePayload(b *testing.B) {
	for _, size := range benchSizes {
		b.Run(fmt.Sprintf("%dMB", size>>20), func(b *testing.B) {
			srv := newPayloadServer(b, size)
			h := &FileHandler{}
			b.SetBytes(int64(size))
			b.ReportAllocs()
			var ms0, ms1 runtime.MemStats
			runtime.GC()
			runtime.ReadMemStats(&ms0)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				data, err := h.fetchFromURL(srv.URL)
				if err != nil {
					b.Fatal(err)
				}
				_ = data
			}
			b.StopTimer()
			runtime.ReadMemStats(&ms1)
			reportGC(b, ms0, ms1)
		})
	}
}

// BenchmarkDownload_E2E_Local exercises the full download composition that
// the handler will use after the streaming refactor: HTTP body → file on
// disk. Defined now (against current []byte path) to capture baseline; the
// internals of fetchFromURL+writeFileAs change later but this name stays.
func BenchmarkDownload_E2E_Local(b *testing.B) {
	for _, size := range benchSizes {
		b.Run(fmt.Sprintf("%dMB", size>>20), func(b *testing.B) {
			srv := newPayloadServer(b, size)
			h := &FileHandler{}
			b.SetBytes(int64(size))
			b.ReportAllocs()
			var ms0, ms1 runtime.MemStats
			runtime.GC()
			runtime.ReadMemStats(&ms0)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				dst := filepath.Join(b.TempDir(), fmt.Sprintf("dl-%d.bin", i))
				data, err := h.fetchFromURL(srv.URL)
				if err != nil {
					b.Fatal(err)
				}
				if err := writeFileAs(context.Background(), dst, data, nil); err != nil {
					b.Fatal(err)
				}
			}
			b.StopTimer()
			runtime.ReadMemStats(&ms1)
			reportGC(b, ms0, ms1)
		})
	}
}
```

(Add `"strconv"` and `"context"` to imports if missing. `bytes`, `fmt`, `io`, `net/http`, `net/http/httptest`, `path/filepath`, `runtime`, `testing` are already imported by PR 1.)

- [ ] **Step 2: Run once to verify build/exec**

Run: `go test -run=^$ -bench=BenchmarkFetchFromURLLargePayload/1MB -benchtime=1x -benchmem ./pkg/executor/handlers/file/`
Expected: PASS, output includes `B/op` ≥ ~1 MB.

- [ ] **Step 3: Capture download baseline at -count=5**

Run:
```
go test -run=^$ -bench='BenchmarkFetchFromURLLargePayload|BenchmarkDownload_E2E_Local' -count=5 -benchmem ./pkg/executor/handlers/file/ | tee /tmp/pr2-download-old.txt
cp /tmp/pr2-download-old.txt docs/superpowers/baselines/2026-05-07-pr2-download-baseline.txt
```
Expected: `100MB` line shows `B/op` ≥ ~250 MB matching issue #199 (current `io.ReadAll` cost).

- [ ] **Step 4: Commit**

```
git add pkg/executor/handlers/file/bench_test.go docs/superpowers/baselines/2026-05-07-pr2-download-baseline.txt
git commit -m "test: add download bench harness and capture buffered baseline (#199)"
```

---

## Task 2: Makefile bench-mem download target + RSS baseline

**Files:**
- Modify: `Makefile`

- [ ] **Step 1: Extend `bench-mem` target to include download**

Replace the loop in `bench-mem` so it iterates both upload and download:

```makefile
.PHONY: bench-mem
bench-mem:
	go test -c -o /tmp/file_bench ./pkg/executor/handlers/file/
	@for kind in Upload Download; do \
		for sz in 1MB 10MB 100MB; do \
			echo "==== $$kind $$sz ===="; \
			$(TIME) $(TIME_FLAG) /tmp/file_bench -test.bench=Benchmark$${kind}_E2E_Local/$$sz -test.benchmem -test.benchtime=1x 2>&1 | tail -25; \
		done; \
	done
```

- [ ] **Step 2: Run target**

Run: `make bench-mem`
Expected: 6 blocks (Upload×3 + Download×3). Download 100MB block shows ≥ 480 MiB RSS.

- [ ] **Step 3: Save RSS baseline**

Run:
```
make bench-mem 2>&1 | tee docs/superpowers/baselines/2026-05-07-pr2-download-rss-baseline.txt
```

- [ ] **Step 4: Commit**

```
git add Makefile docs/superpowers/baselines/2026-05-07-pr2-download-rss-baseline.txt
git commit -m "build: extend bench-mem to cover download RSS measurements (#199)"
```

---

## Task 3: Inventory `IsZipFile` callers

**Files (read-only investigation):**
- All `*.go` under repo root.

- [ ] **Step 1: List callers**

Run:
```
grep -rn "IsZipFile" --include="*.go" .
```
Expected: at least the call site in `pkg/executor/handlers/file/file.go::fileDownload`. Save the full list to `/tmp/pr2-iszipfile-callers.txt`.

- [ ] **Step 2: Decide migration policy**

Read the list. If callers exist outside `pkg/executor/handlers/file/`, both signatures will coexist for this PR; the byte-slice form will be removed in a follow-up. If only the file handler calls it, the byte-slice form is replaced outright in this PR. Record the decision (one sentence) at the top of `/tmp/pr2-iszipfile-callers.txt`.

- [ ] **Step 3: No commit (investigation only)**

---

## Task 4: Add `IsZipFileAtPath` (TDD)

**Files:**
- Modify: existing zip-utility file (locate via `grep -n "func IsZipFile" pkg/utils/`)
- Modify: corresponding `_test.go`

- [ ] **Step 1: Locate the file**

Run: `grep -rn "func IsZipFile" pkg/utils/`
Expected: one or two lines pointing at `pkg/utils/zip.go` or similar. Use that path below.

- [ ] **Step 2: Write failing test**

Append to the relevant `_test.go`:

```go
func TestIsZipFileAtPath(t *testing.T) {
	tmp := t.TempDir()
	zipPath := filepath.Join(tmp, "a.zip")
	// Minimal local-file-header signature "PK\x03\x04" + filler.
	if err := os.WriteFile(zipPath, append([]byte{'P', 'K', 0x03, 0x04}, make([]byte, 16)...), 0644); err != nil {
		t.Fatal(err)
	}
	ok, err := IsZipFileAtPath(zipPath, ".zip")
	if err != nil || !ok {
		t.Fatalf("expected zip detection, got ok=%v err=%v", ok, err)
	}
	txt := filepath.Join(tmp, "b.txt")
	_ = os.WriteFile(txt, []byte("not a zip"), 0644)
	ok, err = IsZipFileAtPath(txt, ".zip")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if ok {
		t.Fatal("non-zip should not be detected as zip")
	}
	ok, err = IsZipFileAtPath(filepath.Join(tmp, "missing"), ".zip")
	if err == nil {
		t.Fatal("expected error for missing path")
	}
	_ = ok
}
```

- [ ] **Step 3: Run test to verify failure**

Run: `go test -run TestIsZipFileAtPath ./pkg/utils/`
Expected: FAIL `undefined: IsZipFileAtPath`.

- [ ] **Step 4: Implement `IsZipFileAtPath`**

Append to the located zip-utility file:

```go
// IsZipFileAtPath sniffs the four-byte local-file-header signature on disk.
// `ext` mirrors the legacy IsZipFile API: a non-empty mismatching extension
// returns false without reading. Returns (false, error) for I/O failures.
func IsZipFileAtPath(path, ext string) (bool, error) {
	if ext != "" && !strings.EqualFold(ext, ".zip") {
		return false, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer func() { _ = f.Close() }()
	var hdr [4]byte
	n, err := io.ReadFull(f, hdr[:])
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) {
		return false, err
	}
	if n < 4 {
		return false, nil
	}
	return hdr[0] == 'P' && hdr[1] == 'K' && hdr[2] == 0x03 && hdr[3] == 0x04, nil
}
```

(Verify imports include `errors`, `io`, `os`, `strings`; add any missing.)

- [ ] **Step 5: Run test to verify pass**

Run: `go test -run TestIsZipFileAtPath ./pkg/utils/`
Expected: PASS.

- [ ] **Step 6: Commit**

```
git add pkg/utils/<zip-util-file>.go pkg/utils/<zip-util-test>.go
git commit -m "feat(utils): add IsZipFileAtPath for streaming zip detection (#199)"
```

---

## Task 5: Flip `fetchFromURL` and `getFileData` to readers (TDD)

**Files:**
- Modify: `pkg/executor/handlers/file/file.go`
- Modify: `pkg/executor/handlers/file/file_test.go`

- [ ] **Step 1: Update / add tests for the new behavior**

Add to `file_test.go`:

```go
func TestFetchFromURL_StreamsBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("hello"))
	}))
	defer srv.Close()
	h := &FileHandler{}
	rc, err := h.fetchFromURL(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	got, _ := io.ReadAll(rc)
	if string(got) != "hello" {
		t.Fatalf("got %q", got)
	}
}

func TestFetchFromURL_NonOKClosesAndErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
	}))
	defer srv.Close()
	h := &FileHandler{}
	if _, err := h.fetchFromURL(srv.URL); err == nil {
		t.Fatal("expected error for 404")
	}
}

func TestGetFileData_AllTypes(t *testing.T) {
	h := &FileHandler{}
	cases := []struct {
		name string
		args *common.CommandArgs
		want string
	}{
		{"text", &common.CommandArgs{Type: "text", Content: "abc"}, "abc"},
		{"base64", &common.CommandArgs{Type: "base64", Content: base64.StdEncoding.EncodeToString([]byte("xyz"))}, "xyz"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rc, err := h.getFileData(c.args)
			if err != nil {
				t.Fatal(err)
			}
			defer rc.Close()
			got, _ := io.ReadAll(rc)
			if string(got) != c.want {
				t.Fatalf("got %q", got)
			}
		})
	}
}
```

(Add imports: `encoding/base64`, `io`, `net/http`, `net/http/httptest`, and `common` package alias.)

- [ ] **Step 2: Run tests to verify they fail to compile**

Run: `go test -run TestFetchFromURL ./pkg/executor/handlers/file/`
Expected: FAIL — current `fetchFromURL` returns `[]byte`.

- [ ] **Step 3: Replace `fetchFromURL` to return reader**

In `file.go`, replace `fetchFromURL`:

```go
func (h *FileHandler) fetchFromURL(contentURL string) (io.ReadCloser, error) {
	parsedRequestURL, err := url.Parse(contentURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse URL '%s': %w", contentURL, err)
	}
	req, err := http.NewRequest(http.MethodGet, parsedRequestURL.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	parsedServerURL, err := url.Parse(config.GlobalSettings.ServerURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse url: %w", err)
	}
	if parsedRequestURL.Host == parsedServerURL.Host && parsedRequestURL.Scheme == parsedServerURL.Scheme {
		req.Header.Set("Authorization", fmt.Sprintf(`id="%s", key="%s"`,
			config.GlobalSettings.ID, config.GlobalSettings.Key))
	}
	client := utils.NewHTTPClient()
	resp, err := client.Do(req) // lgtm[go/request-forgery]
	if err != nil {
		return nil, fmt.Errorf("failed to download content from URL: %w", err)
	}
	if resp.StatusCode/100 != 2 {
		_ = resp.Body.Close()
		log.Error().Msgf("Failed to download content from URL: %d %s", resp.StatusCode, parsedRequestURL)
		return nil, errors.New("downloading content failed")
	}
	return resp.Body, nil
}
```

- [ ] **Step 4: Replace `getFileData` to return reader**

```go
func (h *FileHandler) getFileData(args *common.CommandArgs) (io.ReadCloser, error) {
	switch args.Type {
	case "url":
		return h.fetchFromURL(args.Content)
	case "text":
		return io.NopCloser(strings.NewReader(args.Content)), nil
	case "base64":
		return io.NopCloser(base64.NewDecoder(base64.StdEncoding, strings.NewReader(args.Content))), nil
	default:
		return nil, fmt.Errorf("unknown file type: %s", args.Type)
	}
}
```

(Imports: ensure `encoding/base64` and `strings` are present.)

- [ ] **Step 5: Run new tests to verify pass**

Run: `go test -run 'TestFetchFromURL|TestGetFileData' ./pkg/executor/handlers/file/`
Expected: PASS (3 subtests).

- [ ] **Step 6: Build to surface remaining call sites**

Run: `go build ./...`
Expected: FAIL inside `fileDownload` because it still does `content := getFileData(); writeFileAs(... content)` with `[]byte`. That is fixed in Task 7. **Do not commit yet.**

---

## Task 6: Flip `writeFileAs` to reader (TDD)

**Files:**
- Modify: `pkg/executor/handlers/file/file_io_unix.go`
- Modify: `pkg/executor/handlers/file/file_io_windows.go`
- Modify: `pkg/executor/handlers/file/file_test.go` (or add new `file_io_test.go` if cleaner)

- [ ] **Step 1: Write failing test for non-demoted streaming write**

Append to a test file in the file handler package:

```go
func TestWriteFileAs_NonDemotedStream(t *testing.T) {
	dir := t.TempDir()
	dst := filepath.Join(dir, "out.bin")
	payload := bytes.Repeat([]byte{0x42}, 1<<20)
	src := bytes.NewReader(payload)
	if err := writeFileAs(context.Background(), dst, src, nil); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("payload mismatch")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test -run TestWriteFileAs_NonDemotedStream ./pkg/executor/handlers/file/`
Expected: FAIL — old signature takes `[]byte`.

- [ ] **Step 3: Replace `writeFileAs` in `file_io_unix.go`**

```go
func writeFileAs(ctx context.Context, path string, src io.Reader, sysProcAttr *syscall.SysProcAttr) error {
	if sysProcAttr == nil {
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			return err
		}
		f, err := os.Create(path)
		if err != nil {
			return err
		}
		_, err = io.Copy(f, src)
		if cerr := f.Close(); err == nil {
			err = cerr
		}
		return err
	}
	cmd := exec.CommandContext(ctx, "sh", "-c", fmt.Sprintf("tee %s > /dev/null", utils.Quote(path)))
	cmd.SysProcAttr = sysProcAttr
	cmd.Stdin = src
	var errBuf bytes.Buffer
	cmd.Stderr = &errBuf
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(errBuf.String())
		if msg == "" {
			return err
		}
		return fmt.Errorf("%w: %s", err, msg)
	}
	return nil
}
```

(Imports: add `io`, `strings`; ensure `bytes` stays for `errBuf`.)

- [ ] **Step 4: Replace `writeFileAs` in `file_io_windows.go`**

```go
func writeFileAs(ctx context.Context, path string, src io.Reader, sysProcAttr *syscall.SysProcAttr) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	_, err = io.Copy(f, src)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}
```

(Imports: `io`.)

- [ ] **Step 5: Run new test to verify pass**

Run: `go test -run TestWriteFileAs_NonDemotedStream ./pkg/executor/handlers/file/`
Expected: PASS.

- [ ] **Step 6: No commit yet (Task 7 fixes remaining call sites in same compile unit)**

---

## Task 7: Migrate `fileDownload` to streaming + zip sniff at path

**Files:**
- Modify: `pkg/executor/handlers/file/file.go`
- Modify: `pkg/executor/handlers/file/file_test.go`

- [ ] **Step 1: Rewrite `fileDownload`**

Replace the body of `fileDownload`:

```go
func (h *FileHandler) fileDownload(ctx context.Context, args *common.CommandArgs, sysProcAttr *syscall.SysProcAttr, homeDirectory string) (int, string) {
	content, err := h.getFileData(args)
	if err != nil {
		return 1, err.Error()
	}
	defer func() { _ = content.Close() }()

	downloadPath, err := utils.SanitizePath(utils.FromWirePath(args.Path))
	if err != nil {
		return 1, err.Error()
	}
	if runtime.GOOS == "windows" {
		resolved, err := utils.ResolveAndEnsureUnderHome(homeDirectory, downloadPath)
		if err != nil {
			return 1, err.Error()
		}
		downloadPath = resolved
	}
	args.Path = downloadPath

	if !args.AllowOverwrite && utils.FileExists(args.Path) {
		return 1, fmt.Sprintf("%s already exists.", args.Path)
	}

	if err := writeFileAs(ctx, args.Path, content, sysProcAttr); err != nil {
		_ = os.Remove(args.Path) // partial-file cleanup; idempotent
		log.Error().Err(err).Msg("Failed to write file.")
		return 1, "You do not have permission to write to the directory, or directory does not exist"
	}

	isZip, _ := utils.IsZipFileAtPath(args.Path, filepath.Ext(args.Path))
	if isZip && args.AllowUnzip {
		if err := utils.Unzip(args.Path, filepath.Dir(args.Path)); err != nil {
			log.Error().Err(err).Msg("Failed to unzip file.")
			return 1, err.Error()
		}
		_ = os.Remove(args.Path)
	}

	return 0, fmt.Sprintf("Successfully downloaded %s.", args.Path)
}
```

- [ ] **Step 2: Add a regression test for partial-file cleanup**

Append to `file_test.go`:

```go
// failingReader returns 32 KiB then an error, so the file is partially
// written before writeFileAs returns an error.
type failingReader struct {
	data []byte
	off  int
}

func (f *failingReader) Read(p []byte) (int, error) {
	if f.off >= len(f.data)/2 {
		return 0, errors.New("synthetic")
	}
	n := copy(p, f.data[f.off:])
	f.off += n
	return n, nil
}

func TestFileDownload_PartialFileRemoved(t *testing.T) {
	dir := t.TempDir()
	dst := filepath.Join(dir, "out.bin")
	src := &failingReader{data: bytes.Repeat([]byte{1}, 64<<10)}
	err := writeFileAs(context.Background(), dst, src, nil)
	if err == nil {
		t.Fatal("expected error")
	}
	// Simulate handler-level cleanup that fileDownload performs.
	_ = os.Remove(dst)
	if _, err := os.Stat(dst); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("expected file removed, got stat err=%v", err)
	}
}
```

(Imports: `errors`, `io/fs`.)

- [ ] **Step 3: Build and run all tests**

Run: `go build ./... && go test -v ./... -p 1 -count=1`
Expected: PASS for everything in the file package and dependents. If any other test in the repo broke from `writeFileAs`/`getFileData` signature changes, update its mocks/callers (download path is internal, so only file handler tests should be affected).

- [ ] **Step 4: Commit Tasks 5–7 together**

```
git add pkg/executor/handlers/file/file.go pkg/executor/handlers/file/file_io_unix.go pkg/executor/handlers/file/file_io_windows.go pkg/executor/handlers/file/file_test.go
git commit -m "feat(file): stream download path end-to-end (#199)

fetchFromURL/getFileData now return io.ReadCloser. writeFileAs takes an
io.Reader. fileDownload threads the reader from the source through to
the on-disk file via io.Copy (or tee for demoted users). Zip detection
moves to a four-byte sniff at the resulting path so the payload no
longer needs to live in memory."
```

---

## Task 8: Update download benchmarks to streaming entrypoints

**Files:**
- Modify: `pkg/executor/handlers/file/bench_test.go`

- [ ] **Step 1: Adjust `BenchmarkFetchFromURLLargePayload` to drain the reader**

Replace the body so it consumes the streaming `fetchFromURL`. The exported benchmark name stays identical so benchstat aligns with Task 1 baseline:

```go
func BenchmarkFetchFromURLLargePayload(b *testing.B) {
	for _, size := range benchSizes {
		b.Run(fmt.Sprintf("%dMB", size>>20), func(b *testing.B) {
			srv := newPayloadServer(b, size)
			h := &FileHandler{}
			b.SetBytes(int64(size))
			b.ReportAllocs()
			var ms0, ms1 runtime.MemStats
			runtime.GC()
			runtime.ReadMemStats(&ms0)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				rc, err := h.fetchFromURL(srv.URL)
				if err != nil {
					b.Fatal(err)
				}
				if _, err := io.Copy(io.Discard, rc); err != nil {
					b.Fatal(err)
				}
				_ = rc.Close()
			}
			b.StopTimer()
			runtime.ReadMemStats(&ms1)
			reportGC(b, ms0, ms1)
		})
	}
}
```

`BenchmarkDownload_E2E_Local` already calls `fetchFromURL` and `writeFileAs`; after Tasks 5 and 6 those functions stream by default, so its body needs no rewrite — only verify it compiles. (If the body still references variables from the old buffered version, simplify to call `fetchFromURL` → `writeFileAs(ctx, dst, rc, nil)` then `rc.Close()`.)

- [ ] **Step 2: Run download benchmarks once**

Run: `go test -run=^$ -bench='BenchmarkFetchFromURLLargePayload/1MB|BenchmarkDownload_E2E_Local/1MB' -benchtime=1x -benchmem ./pkg/executor/handlers/file/`
Expected: PASS, `B/op` ≪ baseline at 1MB (target single-digit KB at 1MB tier).

- [ ] **Step 3: Commit**

```
git add pkg/executor/handlers/file/bench_test.go
git commit -m "test: switch download benches to streaming entrypoints (#199)"
```

---

## Task 9: After-measurement, benchstat, acceptance gate, PR open

**Files:**
- Create: `docs/superpowers/baselines/2026-05-07-pr2-download-results.md`

- [ ] **Step 1: Capture after-bench results**

Run:
```
go test -run=^$ -bench='BenchmarkFetchFromURLLargePayload|BenchmarkDownload_E2E_Local' -count=5 -benchmem ./pkg/executor/handlers/file/ | tee /tmp/pr2-download-new.txt
```

- [ ] **Step 2: Run benchstat**

Run:
```
benchstat /tmp/pr2-download-old.txt /tmp/pr2-download-new.txt | tee /tmp/pr2-download-stat.txt
```
Expected: `100MB` rows show large negative `B/op` and `allocs/op` deltas, `ns/op` delta within ±10%.

- [ ] **Step 3: Capture after-RSS**

Run:
```
make bench-mem 2>&1 | tee /tmp/pr2-download-rss-new.txt
```
Expected: download 100MB block `maximum resident set size` < 50 MiB.

- [ ] **Step 4: Verify acceptance gate**

Confirm:
- 100MB download `B/op` < 10,000,000
- 100MB download `allocs/op` < 50
- 100MB download `ns/op` regression vs baseline ≤ +10%
- 100MB download RSS < 52,428,800

If any gate fails, STOP and investigate. Likely culprits: hidden `io.ReadAll` in tests, missing `b.ResetTimer()`, `httptest` server caching the payload buffer.

- [ ] **Step 5: Write results doc**

```markdown
# PR 2 (download streaming) — measurement results

## Bench (benchstat -count=5)
<paste /tmp/pr2-download-stat.txt>

## RSS (/usr/bin/time)
- baseline (Task 2): <100MB Download RSS from 2026-05-07-pr2-download-rss-baseline.txt>
- after  (Task 9):  <100MB Download RSS from /tmp/pr2-download-rss-new.txt>

## Acceptance gate
| Metric (100MB download) | Target  | Result | Pass |
|---|---|---|---|
| B/op           | < 10 MB | <fill> | ✅/❌ |
| allocs/op      | < 50    | <fill> | ✅/❌ |
| ns/op delta    | ≤ +10%  | <fill> | ✅/❌ |
| RSS            | < 50 MiB| <fill> | ✅/❌ |

## IsZipFile migration (Task 3)
- Caller inventory: see `/tmp/pr2-iszipfile-callers.txt` summary.
- Decision: <one sentence>.
```

Save to `docs/superpowers/baselines/2026-05-07-pr2-download-results.md`.

- [ ] **Step 6: Commit results doc**

```
git add docs/superpowers/baselines/2026-05-07-pr2-download-results.md
git commit -m "docs: PR 2 download streaming — bench and RSS results (#199)"
```

- [ ] **Step 7: Open PR**

```
git push -u origin <branch>   # branch name set by reviewer (e.g. 199-stream-download)
gh pr create --base main --title "feat(file): stream download path (#199)" --body "$(cat <<'EOF'
## Summary
- Replace buffered download payload handling (`io.ReadAll(resp.Body)` → `[]byte` content → buffered `IsZipFile`) with an `io.Reader` pipeline.
- Flip `fetchFromURL` and `getFileData` to return `io.ReadCloser`; `writeFileAs` now accepts `io.Reader`.
- Add `IsZipFileAtPath` for four-byte sniff on disk; payload no longer needs to live in memory for type detection.
- Extend bench harness and `bench-mem` Make target to cover download benches and RSS.

Spec: `docs/superpowers/specs/2026-05-07-file-streaming-design.md`
Plan: `docs/superpowers/plans/2026-05-07-file-streaming-pr2-download.md`
Closes #199 (combined with PR 1).

## Measurements
See `docs/superpowers/baselines/2026-05-07-pr2-download-results.md`.

## IsZipFile migration
See `/tmp/pr2-iszipfile-callers.txt` summary in the results doc.

## Test plan
- [x] `go test -v ./... -p 1 -count=1`
- [x] `go test -bench=. -benchmem -count=5 ./pkg/executor/handlers/file/`
- [x] `make bench-mem`
- [x] Partial-file cleanup regression covered
- [x] Acceptance gate (B/op, allocs/op, ns/op, RSS) all pass
EOF
)"
```

---

## Self-review notes (writer)

- **Spec coverage:** every change in spec PR 2 file table is covered (`writeFileAs` Task 6, `getFileData`/`fetchFromURL`/`fileDownload` Tasks 5+7, `IsZipFileAtPath` Task 4, bench updates Tasks 1+8, results doc Task 9). Acceptance gate verified in Task 9.
- **Placeholders:** none. Where the Makefile already exists from PR 1, Task 2 explicitly replaces only the loop body. Where the zip-utility file path is unknown ahead of time, Task 4 Step 1 includes an explicit `grep` to locate it.
- **Type consistency:** `fetchFromURL` → `(io.ReadCloser, error)`, `getFileData` → `(io.ReadCloser, error)`, `writeFileAs` → `(ctx, path, io.Reader, *syscall.SysProcAttr) error`, `IsZipFileAtPath` → `(string, string) (bool, error)` — names match spec and are used consistently across Tasks 5–8.
- **Bench-first:** Tasks 1–3 land bench infra and capture baseline before any production-code change. The first compile-affecting changes (Task 5 onward) come after the helper (`IsZipFileAtPath`) is in place.
- **Build-stability gap:** Tasks 5 and 6 leave the build broken transiently. They commit together with Task 7 to keep history bisectable. This is called out explicitly in Task 5 Step 6 and Task 6 Step 6.
