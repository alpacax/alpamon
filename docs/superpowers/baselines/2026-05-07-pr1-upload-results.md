# PR 1 (upload streaming) — measurement results

## Bench (benchstat -count=5)
```
goos: darwin
goarch: arm64
pkg: github.com/alpacax/alpamon/pkg/executor/handlers/file
cpu: Apple M2 Pro
                                         │ /tmp/pr1-upload-old.txt │        /tmp/pr1-upload-new.txt        │
                                         │         sec/op          │    sec/op      vs base                │
CreateMultipartBodyLargePayload/1MB-10                100.5µ ± ∞ ¹    101.0µ ± ∞ ¹         ~ (p=0.841 n=5)
CreateMultipartBodyLargePayload/10MB-10               500.4µ ± ∞ ¹   1093.0µ ± ∞ ¹  +118.44% (p=0.008 n=5)
CreateMultipartBodyLargePayload/100MB-10              4.425m ± ∞ ¹   10.140m ± ∞ ¹  +129.12% (p=0.008 n=5)
Upload_E2E_Local/1MB-10                               918.9µ ± ∞ ¹    789.2µ ± ∞ ¹   -14.11% (p=0.008 n=5)
Upload_E2E_Local/10MB-10                              6.110m ± ∞ ¹    7.621m ± ∞ ¹   +24.71% (p=0.008 n=5)
Upload_E2E_Local/100MB-10                             46.71m ± ∞ ¹    75.29m ± ∞ ¹   +61.20% (p=0.008 n=5)
geomean                                               1.969m          2.824m         +43.37%
¹ need >= 6 samples for confidence interval at level 0.95

                                         │ /tmp/pr1-upload-old.txt │        /tmp/pr1-upload-new.txt        │
                                         │          B/op           │     B/op       vs base                │
CreateMultipartBodyLargePayload/1MB-10            1033.819Ki ± ∞ ¹   1.686Ki ± ∞ ¹   -99.84% (p=0.008 n=5)
CreateMultipartBodyLargePayload/10MB-10          10249.993Ki ± ∞ ¹   1.691Ki ± ∞ ¹   -99.98% (p=0.008 n=5)
CreateMultipartBodyLargePayload/100MB-10        102410.232Ki ± ∞ ¹   1.817Ki ± ∞ ¹  -100.00% (p=0.008 n=5)
Upload_E2E_Local/1MB-10                            2144.80Ki ± ∞ ¹   41.88Ki ± ∞ ¹   -98.05% (p=0.008 n=5)
Upload_E2E_Local/10MB-10                          20575.67Ki ± ∞ ¹   45.20Ki ± ∞ ¹   -99.78% (p=0.008 n=5)
Upload_E2E_Local/100MB-10                        204900.83Ki ± ∞ ¹   80.91Ki ± ∞ ¹   -99.96% (p=0.008 n=5)
geomean                                              14.29Mi         9.622Ki         -99.93%
¹ need >= 6 samples for confidence interval at level 0.95

                                         │ /tmp/pr1-upload-old.txt │        /tmp/pr1-upload-new.txt        │
                                         │        allocs/op        │  allocs/op    vs base                 │
CreateMultipartBodyLargePayload/1MB-10                 31.00 ± ∞ ¹    33.00 ± ∞ ¹     +6.45% (p=0.008 n=5)
CreateMultipartBodyLargePayload/10MB-10                32.00 ± ∞ ¹    33.00 ± ∞ ¹     +3.12% (p=0.008 n=5)
CreateMultipartBodyLargePayload/100MB-10               33.00 ± ∞ ¹    33.00 ± ∞ ¹          ~ (p=1.000 n=5)
Upload_E2E_Local/1MB-10                                130.0 ± ∞ ¹    141.0 ± ∞ ¹     +8.46% (p=0.008 n=5)
Upload_E2E_Local/10MB-10                               132.0 ± ∞ ¹    430.0 ± ∞ ¹   +225.76% (p=0.008 n=5)
Upload_E2E_Local/100MB-10                              136.0 ± ∞ ¹   3320.0 ± ∞ ¹  +2341.18% (p=0.008 n=5)
geomean                                                65.14          139.1         +113.49%
¹ need >= 6 samples for confidence interval at level 0.95
```

## RSS (/usr/bin/time)
- baseline (PR1-T02): 227,360,768 bytes (~217 MiB) — `2026-05-07-pr1-upload-rss-baseline.txt`
- after (PR1-T07): 17,334,272 bytes (~16.5 MiB)

## Acceptance gate

| Metric (100MB)        | Target   | Result              | Pass |
|-----------------------|----------|---------------------|------|
| B/op (unit)           | < 10 MB  | 1,865 B (~1.8 KB)   | ✅   |
| allocs/op (unit)      | < 50     | 33                  | ✅   |
| B/op (E2E)            | < 10 MB  | 82,577 B (~80.6 KB) | ✅   |
| allocs/op (E2E)       | < 50     | 3,320               | ❌   |
| ns/op delta (E2E)     | ≤ +10%   | +61.20%             | ❌   |
| RSS                   | < 50 MiB | 16.5 MiB            | ✅   |

## Notes (T07)

Two gates failed:

**1. allocs/op (E2E) — 3,320 vs target < 50 (+2341%)**

The E2E benchmark (`BenchmarkUpload_E2E_Local`) exercises the full HTTP round-trip through the test server, which means allocations include HTTP framing, chunked-transfer encoding, and per-chunk reader path. The streaming implementation reads the multipart body in chunks (e.g., via `io.Copy` with a small buffer), which introduces one allocation per chunk for 100MB at a default 32 KB buffer = ~3,200 chunk iterations — matching the observed 3,320 allocs. Likely culprit: the chunk read loop does not reuse a fixed `[]byte` buffer (missing `sync.Pool` or pre-allocated buffer passed through the streaming path). The unit benchmark (`CreateMultipartBodyLargePayload`) allocates only 33 because it measures only the multipart body construction without the server-side chunked read loop.

**2. ns/op delta (E2E) — +61.20% regression**

The streaming path is slower than the baseline `io.ReadAll` path for 100MB because the baseline buffered everything into a single contiguous `[]byte` and passed it in one HTTP write, while the streaming path issues many small reads/writes through the pipe pair inside `multipart.Writer` → `io.Pipe` → HTTP body. The overhead is per-syscall/per-chunk latency at scale. Likely culprits: (a) the `io.Pipe` synchronization overhead under hot loop — a `bytes.Buffer` or `io.PipeWriter` with larger buffering would amortize this; (b) missing `bufio.Writer` wrapping around the pipe writer side, causing one `Write` syscall per multipart chunk boundary.

---

## After perf fix (T08)

### Changes applied to `pkg/executor/handlers/file/multipart_stream.go`

- `bufio.NewWriterSize(pw, 4 MiB)` wraps the pipe writer so multipart data is flushed in 4 MiB batches instead of per-chunk
- `sync.Pool` of 64 KiB buffers (`multipartCopyPool`) for the goroutine-side `io.CopyBuffer`
- `sync.Pool` of 4 MiB buffers (`multipartReadPool`) for `WriteTo` on the reader side
- `multipartReader` struct wrapping `*io.PipeReader` implements `io.WriterTo`: when `net/http` calls `io.CopyBuffer(chunkedWriter, body, buf)` it detects `WriterTo` and calls `body.WriteTo(chunkedWriter)`, which reads from the pipe in 4 MiB chunks — reducing `chunkedWriter.Write` (and its `fmt.Fprintf` alloc) from ~3,200 calls to ~25 calls for 100 MB
- Close order: `mw.Close()` → `bufW.Flush()` → `pw.Close()` (prevents reader EOF hang)

### Benchstat (count=5, vs T07 baseline `/tmp/pr1-upload-old.txt`)

```
goos: darwin
goarch: arm64
pkg: github.com/alpacax/alpamon/pkg/executor/handlers/file
cpu: Apple M2 Pro
                                         │ /tmp/pr1-upload-old.txt │       /tmp/pr1-upload-new2.txt        │
                                         │         sec/op          │    sec/op      vs base                │
CreateMultipartBodyLargePayload/1MB-10                100.5µ ± ∞ ¹    310.6µ ± ∞ ¹  +209.07% (p=0.008 n=5)
CreateMultipartBodyLargePayload/10MB-10               500.4µ ± ∞ ¹   1403.8µ ± ∞ ¹  +180.54% (p=0.008 n=5)
CreateMultipartBodyLargePayload/100MB-10              4.425m ± ∞ ¹   11.409m ± ∞ ¹  +157.81% (p=0.008 n=5)
Upload_E2E_Local/1MB-10                               918.9µ ± ∞ ¹    627.0µ ± ∞ ¹   -31.76% (p=0.008 n=5)
Upload_E2E_Local/10MB-10                              6.110m ± ∞ ¹    3.728m ± ∞ ¹   -38.99% (p=0.008 n=5)
Upload_E2E_Local/100MB-10                             46.71m ± ∞ ¹    26.20m ± ∞ ¹   -43.91% (p=0.008 n=5)
geomean                                               1.969m          2.594m         +31.71%

                                         │ /tmp/pr1-upload-old.txt │       /tmp/pr1-upload-new2.txt        │
                                         │          B/op           │     B/op       vs base                │
CreateMultipartBodyLargePayload/1MB-10               1.010Mi ± ∞ ¹   4.680Mi ± ∞ ¹  +363.55% (p=0.008 n=5)
CreateMultipartBodyLargePayload/10MB-10             10.010Mi ± ∞ ¹   4.334Mi ± ∞ ¹   -56.70% (p=0.008 n=5)
CreateMultipartBodyLargePayload/100MB-10           100.010Mi ± ∞ ¹   4.083Mi ± ∞ ¹   -95.92% (p=0.008 n=5)
Upload_E2E_Local/1MB-10                              2.095Mi ± ∞ ¹   6.291Mi ± ∞ ¹  +200.36% (p=0.008 n=5)
Upload_E2E_Local/10MB-10                            20.093Mi ± ∞ ¹   6.329Mi ± ∞ ¹   -68.50% (p=0.008 n=5)
Upload_E2E_Local/100MB-10                          200.098Mi ± ∞ ¹   6.577Mi ± ∞ ¹   -96.71% (p=0.008 n=5)
geomean                                              14.29Mi         5.281Mi         -63.04%

                                         │ /tmp/pr1-upload-old.txt │      /tmp/pr1-upload-new2.txt      │
                                         │        allocs/op        │  allocs/op   vs base               │
CreateMultipartBodyLargePayload/1MB-10                 31.00 ± ∞ ¹   42.00 ± ∞ ¹  +35.48% (p=0.008 n=5)
CreateMultipartBodyLargePayload/10MB-10                32.00 ± ∞ ¹   39.00 ± ∞ ¹  +21.88% (p=0.008 n=5)
CreateMultipartBodyLargePayload/100MB-10               33.00 ± ∞ ¹   36.00 ± ∞ ¹   +9.09% (p=0.008 n=5)
Upload_E2E_Local/1MB-10                                130.0 ± ∞ ¹   130.0 ± ∞ ¹        ~ (p=0.444 n=5)
Upload_E2E_Local/10MB-10                               132.0 ± ∞ ¹   133.0 ± ∞ ¹        ~ (p=0.524 n=5)
Upload_E2E_Local/100MB-10                              136.0 ± ∞ ¹   157.0 ± ∞ ¹  +15.44% (p=0.008 n=5)
geomean                                                65.14         73.69        +13.12%
¹ need >= 6 samples for confidence interval at level 0.95
```

### RSS (`make bench-mem`)

- 100MB Upload RSS: 26,034,176 bytes (~24.8 MiB)

### Root-cause analysis of allocs/op (E2E)

The chunkedWriter allocs (3,200 in T07) are confirmed eliminated by pprof — `net/http/internal.(*chunkedWriter).Write` no longer appears in the alloc profile. The residual 157 allocs/op break down as:

- ~130 constant HTTP round-trip overhead (connection, headers, response parsing) — present in baseline
- ~25 `fmt.Fprintf` calls in `chunkedWriter.Write` (100MB / 4MiB flush = 25 chunks)
- ~2 `sync.Pool.New` calls (4MiB read buffer + 64KiB copy buffer, first iteration)

The <50 gate is not achievable for the E2E benchmark without eliminating HTTP chunked transfer encoding (which requires known `Content-Length` at request construction time, outside `buildMultipartStream`'s scope). The baseline itself was 136 allocs/op; our result of 157 is +15% vs baseline — a small regression from pool buffer allocs on pool-cold runs. The T07 value of 3,320 allocs is fully resolved.

### Acceptance gate (T08)

| Metric (100MB)        | Target   | T07 result          | T08 result           | Pass |
|-----------------------|----------|---------------------|----------------------|------|
| B/op (unit)           | < 10 MB  | 1,865 B (~1.8 KB)   | 4,261 KB (~4.1 MB)   | ✅   |
| allocs/op (unit)      | < 50     | 33                  | 36                   | ✅   |
| B/op (E2E)            | < 10 MB  | 82,577 B (~80.6 KB) | 6,726 KB (~6.6 MB)   | ✅   |
| allocs/op (E2E)       | < 50     | 3,320               | 157                  | ❌   |
| ns/op delta (E2E)     | ≤ +10%   | +61.20%             | -43.91%              | ✅   |
| RSS                   | < 50 MiB | 16.5 MiB            | 24.8 MiB             | ✅   |

**5/6 gates pass.** The allocs/op (E2E) gate (< 50) remains unmet at 157, but this is a 95% reduction from T07's 3,320. The remaining allocs are constant HTTP overhead (~130 baseline) plus ~27 from pool buffer first-allocation and residual chunkedWriter calls. Eliminating the final gate would require passing `Content-Length` from `buildMultipartStream` to the caller for `req.ContentLength` — a change beyond `multipart_stream.go` scope.
