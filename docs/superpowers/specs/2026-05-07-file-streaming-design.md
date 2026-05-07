# File transfer streaming refactor

- **Date**: 2026-05-07
- **Issue**: [alpacax/alpamon#199](https://github.com/alpacax/alpamon/issues/199)
- **Status**: Draft (awaiting user review)
- **Owner**: Jisung Chae

## Problem

`pkg/executor/handlers/file/file.go` loads entire file payloads into memory on
both upload and download paths. Measurements at the 100MB level (issue #199):

| Path | `B/op` | `allocs/op` | RSS (`/usr/bin/time -l`) | Dominant cost (alloc_space) |
|---|---|---|---|---|
| Upload | 104,867,314 | 31 | 449,118,208 (~428 MiB) | `bytes.growSlice` 78.26% |
| Download | 252,214,637 | 200 | 523,845,632 (~500 MiB) | `io.ReadAll` 89.63% |

Hot spots:
- `pkg/executor/handlers/file/file.go:145` — `readFileAs` returns `[]byte`
- `pkg/executor/handlers/file/file.go:151` — `createMultipartBody` builds an
  in-memory `bytes.Buffer`
- `pkg/executor/handlers/file/file.go:468` — `io.ReadAll(resp.Body)` consumes
  the full HTTP response

The same payload is held twice on upload (file → `[]byte` → multipart buffer)
and `bytes.Buffer` doubling causes ~3× the payload size in cumulative
allocations. Concurrent transfers compound GC pressure and OOM risk.

## Goals

1. Replace buffered transfer paths with `io.Reader`/`io.Writer` pipelines so
   peak memory is bounded by buffer/window size, not payload size.
2. Preserve current behavior on every functional axis: privilege demotion,
   archive (zip) handling, `useBlob` raw PUT, multipart upload, URL/text/base64
   download, `AllowOverwrite`/`AllowUnzip`, timeouts, ctx cancellation.
3. Land verifiable improvements: micro-benchmarks, RSS measurement, and
   benchstat-based before/after evidence.

## Non-goals

- Resumable / chunked upload protocol changes.
- Server-side (alpacon-server) changes.
- Increasing per-buffer size or tuning OS pipe buffers beyond Go defaults.
- Changing the FTP path (`pkg/runner/ftp.go`).

## Architecture

### Component layout

```
pkg/executor/handlers/file/
  file.go                       handleUpload / handleDownload (flow only)
  file_io_unix.go               readFileAs, writeFileAs (build !windows)
  file_io_windows.go            readFileAs, writeFileAs (build windows)
  cmd_reader_unix.go    NEW     cmdReadCloser helper (build !windows)
  cmd_reader_windows.go NEW     stub (build windows; not used)
  multipart_stream.go   NEW     buildMultipartStream (io.Pipe + goroutine)
  bench_test.go         NEW     benchmarks (E2E_Local + isolated)

pkg/executor/handlers/common/interfaces.go
  APISession.MultipartRequest    signature changes (bytes.Buffer → io.Reader)

pkg/scheduler/session.go
  MultipartRequest               implementation updated to consume io.Reader

pkg/utils/http_client.go
  Put                            signature changes (bytes.Buffer → io.Reader + contentLength)

pkg/utils/zip.go (or current location of IsZipFile)
  IsZipFileAtPath       NEW     four-byte sniff at path
```

### Component responsibilities

| Component | Input | Output | Responsibility |
|---|---|---|---|
| `cmdReadCloser` | `*exec.Cmd` (before Start) | `io.ReadCloser` | Expose a demoted process's stdout as a streaming reader. `Close()` closes stdout, runs `cmd.Wait()`, wraps non-zero exit with captured stderr. Idempotent. |
| `readFileAs` | `ctx, path, sysProcAttr` | `(io.ReadCloser, int64, error)` | Demoted: `exec.Cmd("cat", path)` wrapped by `cmdReadCloser`. Non-demoted: `os.Open`. Size: `os.Stat` performed by alpamon (root) so demoted access is not required. |
| `writeFileAs` | `ctx, path, src io.Reader, sysProcAttr` | `error` | Demoted: `exec.Cmd("sh", "-c", "tee … > /dev/null")` with `cmd.Stdin = src`, `cmd.Run()`. Non-demoted: `os.Create` + `io.Copy`. Wrap non-zero exit with stderr. |
| `buildMultipartStream` | `src io.ReadCloser, fileName, isRecursive` | `(io.ReadCloser, contentType, error)` | `io.Pipe()` + goroutine that drives `multipart.Writer`. Errors propagate via `pw.CloseWithError`. Goroutine owns `src.Close()`. |
| `getFileData` | `*common.CommandArgs` | `(io.ReadCloser, error)` | text → `nopCloser(strings.NewReader(...))`. base64 → `nopCloser(base64.NewDecoder(StdEncoding, strings.NewReader(...)))`. url → `fetchFromURL`. |
| `fetchFromURL` | URL string | `(io.ReadCloser, error)` | Issues `http.Get`. Non-2xx → close body and return error. Caller owns close on success. |

### Invariants

- Every `io.ReadCloser` returned by these helpers MUST be closed by the caller
  via `defer`, regardless of HTTP transport behavior. All `Close` methods are
  idempotent.
- `buildMultipartStream`'s goroutine owns `src.Close()` to prevent leaks when
  the pipe reader is closed early.
- Stderr buffers attached to demoted processes are bounded by realistic
  diagnostic output (kilobytes); they do not contribute to payload-scale
  memory growth.

## Data flow

### Upload (`handleUpload`)

```
parsePaths → makeArchive (single|zip)
  → readFileAs(ctx, name, sysProcAttr)
       non-demoted: os.Open               → *os.File         (size = stat.Size)
       demoted:     cat via cmdReadCloser → cmdReadCloser    (size = root os.Stat)
  → buildMultipartStream(src, base, recursive)        (skipped if useBlob=true)
       io.Pipe + goroutine: multipart.Writer drives io.Copy(fw, src)
       returns (pr, contentType)
  → fileUpload
       useBlob=true:  utils.Put(url, src,  size, timeout)               // ContentLength = size
       useBlob=false: apiSession.MultipartRequest(url, pr, ct, timeout) // ContentLength = -1 (chunked)
  → defer body.Close(), src.Close(), os.Remove(archive)
```

Memory footprint: OS pipe buffers (~64 KiB) plus multipart boundary metadata
plus stderr capture. Independent of payload size.

### Download (`fileDownload`)

```
getFileData(args)
  text   → nopCloser(strings.NewReader(args.Content))
  base64 → nopCloser(base64.NewDecoder(StdEncoding, strings.NewReader(args.Content)))
  url    → fetchFromURL(args.Content)         // non-2xx closes body and errors
  → io.ReadCloser content
  → SanitizePath / ResolveAndEnsureUnderHome (existing logic)
  → AllowOverwrite check (existing logic)
  → writeFileAs(ctx, args.Path, content, sysProcAttr)
       non-demoted: os.Create + io.Copy
       demoted:     sh -c "tee path > /dev/null" with cmd.Stdin = content
  → defer content.Close()
  → IsZipFileAtPath(args.Path, ext) && AllowUnzip
       → utils.Unzip(args.Path, filepath.Dir(args.Path)); os.Remove(args.Path)
```

Memory footprint: `io.Copy` default 32 KiB buffer.

### Zip sniff strategy

Replace `IsZipFile(content []byte, ext string)` with
`IsZipFileAtPath(path, ext string) (bool, error)`.

- Implementation: `os.Open(path)` → `Read(buf[:4])` → check PK signature.
- Reason: streaming write means the payload is no longer in memory after the
  copy, but the file is on disk; a 4-byte read is constant-time.
- Alternative considered: `bufio.Reader.Peek` + `io.TeeReader` for in-flight
  sniff. Rejected because the demoted write path uses a `tee` subprocess,
  which complicates dual consumption of the reader.

Other callers of `IsZipFile([]byte, string)` will be inventoried in PR 2.
If callers exist outside the file handler, both signatures will coexist until
all are migrated; the byte-slice form will then be removed.

## Error handling and cancellation

### Resource recovery matrix

| Scenario | Upload (file → multipart → http) | Download (http → file) |
|---|---|---|
| Normal | http send completes → server EOF → multipart goroutine returns → `pw.Close()` → reader EOF → caller `body.Close()` → `src.Close()` → cat stdout EOF → `cmd.Wait()` returns 0 | response body fully read → tee stdin EOF → tee exits 0 → `cmd.Wait()` returns 0 → caller `resp.Body.Close()` |
| Ctx canceled | `exec.CommandContext` SIGKILL → cat exits → `src.Read` returns wrapped error → `pw.CloseWithError(err)` → http transport read error → request aborts → caller defers run | tee SIGKILL → `cmd.Wait` error; resp body Close from defer |
| Permission denied / missing file | cat exits non-zero → `cmdReadCloser.Close()` returns wrapped error including stderr → multipart goroutine `pw.CloseWithError` | tee exits non-zero → `writeFileAs` returns wrapped error |
| HTTP non-2xx (upload) | caller closes response body → multipart `src.Read` sees `ErrClosedPipe` → goroutine cleanup runs | n/a |
| HTTP non-2xx (download) | n/a | `fetchFromURL` closes body and returns error before `writeFileAs` is called |
| `pw.Write` panic (defensive) | recover → `pw.CloseWithError(panicErr)` → `src.Close` | n/a |

### Key patterns

**`cmdReadCloser`**

```go
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
        return fmt.Errorf("%w: %s", werr, strings.TrimSpace(r.stderr.String()))
    }
    return nil
}
```

**`buildMultipartStream`**

```go
func buildMultipartStream(src io.ReadCloser, fileName string, isRecursive bool) (io.ReadCloser, string, error) {
    pr, pw := io.Pipe()
    mw := multipart.NewWriter(pw)
    contentType := mw.FormDataContentType()

    go func() {
        defer src.Close()
        defer func() {
            if r := recover(); r != nil {
                _ = pw.CloseWithError(fmt.Errorf("multipart panic: %v", r))
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

**`writeFileAs` (demoted branch)**

```go
cmd := exec.CommandContext(ctx, "sh", "-c", fmt.Sprintf("tee %s > /dev/null", utils.Quote(path)))
cmd.SysProcAttr = attr
cmd.Stdin = src
var errBuf bytes.Buffer
cmd.Stderr = &errBuf
if err := cmd.Run(); err != nil {
    return fmt.Errorf("%w: %s", err, strings.TrimSpace(errBuf.String()))
}
```

`tee` may write the bytes received before `src` errors. The handler removes
partial files on `writeFileAs` error via `os.Remove(path)` (idempotent).

### Policy

- All `io.ReadCloser`s closed by caller via `defer`. HTTP transport may also
  close, but the helpers' `Close` methods must be idempotent.
- Wrapped errors include captured stderr from demoted processes for
  diagnostics (path, permission, syscall messages).
- Partial-file cleanup on `writeFileAs` error is the handler's responsibility.
- `WithHandlerTimeout(ctx, FileTimeout)` (existing) propagates to
  `exec.CommandContext` and `http.Request.WithContext` as today.

## Interface changes

### Direct signature replacement (no compat shims)

Each callsite is internal to alpamon and counted (one each), so signatures
are replaced in place.

```go
// common/interfaces.go
type APISession interface {
    MultipartRequest(url string, body io.Reader, contentType string, timeout time.Duration) ([]byte, int, error)
}

// utils/http_client.go
func Put(url string, body io.Reader, contentLength int64, timeout time.Duration) ([]byte, int, error)

// file_io_unix.go / file_io_windows.go
func readFileAs(ctx context.Context, path string, sysProcAttr *syscall.SysProcAttr) (io.ReadCloser, int64, error)
func writeFileAs(ctx context.Context, path string, src io.Reader, sysProcAttr *syscall.SysProcAttr) error

// file.go (handler)
func (h *FileHandler) buildMultipartStream(src io.ReadCloser, fileName string, isRecursive bool) (io.ReadCloser, string, error)
func (h *FileHandler) getFileData(args *common.CommandArgs) (io.ReadCloser, error)
func (h *FileHandler) fetchFromURL(contentURL string) (io.ReadCloser, error)
```

### Content-Length policy

| Path | ContentLength | Encoding |
|---|---|---|
| `useBlob = true` (raw PUT) | known via `os.Stat` (single file or generated archive) | identity, exact length |
| Multipart upload | unknown ahead of time (boundary + form overhead) | `Transfer-Encoding: chunked` (`-1`) |

Multipart boundary pre-computation was considered. Rejected: chunked overhead
is constant per chunk and negligible at payload scale, while pre-computation
forces a stat-and-rebuild before each upload.

## Testing strategy

### Unit tests

- `cmd_reader_unix_test.go` (build `!windows`)
  - Read until EOF, then `Close` returns `nil`.
  - `cat /nonexistent` → `Close` returns wrapped error containing stderr.
  - Double `Close` is idempotent.
  - Read partial bytes then `Close` → cat receives broken pipe and exits.
  - `exec.CommandContext` with canceled ctx → SIGKILL → `Close` reports error.
- `multipart_stream_test.go`
  - 1 MiB src → multipart parsed: boundary, `Content-Disposition`, body equality.
  - `isRecursive = true` → `name` form field present.
  - `src.Read` errors → pipe reader returns the same error.
  - Pipe reader closed early → `src.Close()` is invoked; goroutine count
    settles to baseline.
- `file_io_*_test.go`
  - Non-demoted `writeFileAs`: 1 MiB reader → file content SHA-256 matches.
  - Non-demoted `readFileAs`: 1 MiB file → reader content SHA-256 matches; size matches `os.Stat`.
  - Demoted branches use `t.Skip` unless `os.Geteuid() == 0`.
- `getFileData_test.go`
  - text/base64 valid + invalid base64.
  - url path uses `httptest.NewServer`.

### Integration tests (`file_test.go`)

- `httptest.NewServer` provides multipart sink and download payload.
- `handleUpload` end-to-end: temp source files → handler → mock server
  receives parsable multipart with expected fields and bytes.
- `handleDownload` end-to-end: mock server payload → handler writes file →
  on-disk SHA-256 matches.
- Regressions: `AllowOverwrite=false` with existing file, `AllowUnzip` true
  with zip payload, ctx timeout midway through transfer.

### Benchmarks (`bench_test.go`)

```
BenchmarkUpload_E2E_Local/{1MB,10MB,100MB}
BenchmarkDownload_E2E_Local/{1MB,10MB,100MB}
BenchmarkBuildMultipartStream/{1MB,10MB,100MB}
BenchmarkFetchStream/{1MB,10MB,100MB}
BenchmarkCreateMultipartBodyLargePayload/100MB     // name preserved from issue
BenchmarkFetchFromURLLargePayload/100MB            // name preserved from issue
```

Each benchmark calls `b.SetBytes(int64(size))`, `b.ReportAllocs()`, and
records GC count and pause-ns deltas via `b.ReportMetric`.

### RSS measurement

`Makefile` target `bench-mem` builds the test binary with `go test -c` and
runs it under `/usr/bin/time` with `-test.benchtime=1x` for a single
representative iteration:

```makefile
bench-mem:
	go test -c -o /tmp/file_bench ./pkg/executor/handlers/file/
	@for sz in 1MB 10MB 100MB; do \
		echo "==== upload $$sz ===="; \
		/usr/bin/time -l /tmp/file_bench -test.bench=BenchmarkUpload_E2E_Local/$$sz -test.benchmem -test.benchtime=1x 2>&1 | tail -20; \
		echo "==== download $$sz ===="; \
		/usr/bin/time -l /tmp/file_bench -test.bench=BenchmarkDownload_E2E_Local/$$sz -test.benchmem -test.benchtime=1x 2>&1 | tail -20; \
	done
```

`/usr/bin/time -l` is BSD/macOS; on the Linux production target the same
target uses `/usr/bin/time -v`. The Makefile detects OS and selects flags.

### benchstat report (PR description)

Required in each PR description:

```
## Bench (benchstat -count=10)

### Upload (or Download)
                         before        after        delta
BenchmarkXxx/100MB       X ns/op       Y ns/op      −Z%
                         A B/op        B B/op       −C%
                         P allocs/op   Q allocs/op  −R%

### RSS (/usr/bin/time)
upload 100MB:   428 MiB → ?? MiB
download 100MB: 500 MiB → ?? MiB
```

### CI

`.github/workflows/bench.yml` (new):
- Triggers: nightly cron, `workflow_dispatch`.
- Runs `go test -bench=. -benchmem -count=5 -run=^$ ./pkg/executor/handlers/file/`.
- Uploads result text as artifact.
- Automated regression gate (`benchstat` threshold check) is deferred to a
  follow-up issue.

### Acceptance gates

| Metric (100MB) | Upload | Download |
|---|---|---|
| `B/op` | < 10 MB | < 10 MB |
| `allocs/op` | < 50 | < 50 |
| `ns/op` regression vs main | ≤ +10% | ≤ +10% |
| RSS (`/usr/bin/time`) | < 50 MiB | < 50 MiB |

Baseline: 104 MB / 252 MB `B/op`, 428 / 500 MiB RSS. Targets are roughly 1/10
the baseline.

## PR plan

### PR 1 — `feat: stream upload path + bench infrastructure`

Scope: upload streaming end-to-end plus benchmark and CI infrastructure.
Download path is left untouched.

Files touched:

| State | Path |
|---|---|
| New | `pkg/executor/handlers/file/cmd_reader_unix.go` |
| New | `pkg/executor/handlers/file/cmd_reader_windows.go` (stub) |
| New | `pkg/executor/handlers/file/multipart_stream.go` |
| Modified | `pkg/executor/handlers/file/file_io_unix.go` (`readFileAs` only; `writeFileAs` untouched to keep download path working) |
| Modified | `pkg/executor/handlers/file/file_io_windows.go` (`readFileAs` only) |
| Modified | `pkg/executor/handlers/file/file.go` (handleUpload only) |
| Modified | `pkg/executor/handlers/common/interfaces.go` |
| Modified | `pkg/scheduler/session.go` |
| Modified | `pkg/utils/http_client.go` |
| New | `pkg/executor/handlers/file/cmd_reader_unix_test.go` |
| New | `pkg/executor/handlers/file/multipart_stream_test.go` |
| Modified | `pkg/executor/handlers/file/file_test.go` |
| New | `pkg/executor/handlers/file/bench_test.go` |
| Modified | `Makefile` |
| New | `.github/workflows/bench.yml` |

PR description must include:
- Issue #199 link.
- benchstat upload before/after with `-count=5`.
- `/usr/bin/time -l` RSS upload before/after.
- Acceptance-gate table marked pass/fail.

Risks and notes:
- `getFileData` is not changed in PR 1; `handleUpload` does not use it, so
  there is no impact on the download flow.
- Demoted-path unit tests skip unless `os.Geteuid() == 0`. Confirm whether
  existing CI runs a root-capable job before relying on it; otherwise file a
  follow-up to add one.

### PR 2 — `feat: stream download path`

Depends on PR 1 being merged.

Scope: download streaming end-to-end and zip-sniff strategy change.

Files touched:

| State | Path |
|---|---|
| Modified | `pkg/executor/handlers/file/file_io_unix.go` (`writeFileAs` only) |
| Modified | `pkg/executor/handlers/file/file_io_windows.go` (`writeFileAs` only) |
| Modified | `pkg/executor/handlers/file/file.go` (`getFileData` and `fetchFromURL` signatures, `fileDownload` flow) |
| Modified | `pkg/utils/<zip util location>` (`IsZipFileAtPath` added; byte-slice form removed once callers migrate) |
| Modified | `pkg/executor/handlers/file/file_test.go` |
| Modified | `pkg/executor/handlers/file/bench_test.go` |

PR description must include:
- benchstat download before/after.
- RSS download before/after.
- Inventory of `IsZipFile([]byte, string)` callers and migration outcome.

Risks and notes:
- `IsZipFile` may have callers outside the file handler. PR 2 grep results
  must be included; both signatures coexist until all callers are migrated.
- Add a regression test: `writeFileAs` failure causes handler to remove
  partial file via `os.Remove(args.Path)`.

### Milestones

| Time | Output | Verification |
|---|---|---|
| T-0 (today) | Spec written, user-reviewed | Brainstorming → writing-plans handoff |
| T+1 | PR 1 opened (upload + bench) | benchstat upload meets gate |
| T+2 | PR 1 merged | nightly bench workflow first run |
| T+3 | PR 2 opened (download) | benchstat download meets gate |
| T+4 | PR 2 merged, issue #199 closed | both paths RSS < 50 MiB |

### Rollback

Each PR is independently revertable. Signature changes within a PR are
self-contained. If both PRs are merged and a rollback is required, revert in
reverse order (PR 2 then PR 1).

## Out-of-scope follow-ups

- Automated benchstat regression gate in CI (compare against tip-of-main).
- Resumable / chunked upload protocol for files larger than disk-temp budget.
- Tuning `io.CopyBuffer` size if profiling shows syscall overhead in the
  hot path (default 32 KiB is expected to be sufficient).

## Open questions

None at spec time. To be re-evaluated after PR 1 baseline measurements.
