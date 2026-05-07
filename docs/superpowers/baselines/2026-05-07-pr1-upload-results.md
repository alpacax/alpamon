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

## Notes

Two gates failed:

**1. allocs/op (E2E) — 3,320 vs target < 50 (+2341%)**

The E2E benchmark (`BenchmarkUpload_E2E_Local`) exercises the full HTTP round-trip through the test server, which means allocations include HTTP framing, chunked-transfer encoding, and per-chunk reader path. The streaming implementation reads the multipart body in chunks (e.g., via `io.Copy` with a small buffer), which introduces one allocation per chunk for 100MB at a default 32 KB buffer = ~3,200 chunk iterations — matching the observed 3,320 allocs. Likely culprit: the chunk read loop does not reuse a fixed `[]byte` buffer (missing `sync.Pool` or pre-allocated buffer passed through the streaming path). The unit benchmark (`CreateMultipartBodyLargePayload`) allocates only 33 because it measures only the multipart body construction without the server-side chunked read loop.

**2. ns/op delta (E2E) — +61.20% regression**

The streaming path is slower than the baseline `io.ReadAll` path for 100MB because the baseline buffered everything into a single contiguous `[]byte` and passed it in one HTTP write, while the streaming path issues many small reads/writes through the pipe pair inside `multipart.Writer` → `io.Pipe` → HTTP body. The overhead is per-syscall/per-chunk latency at scale. Likely culprits: (a) the `io.Pipe` synchronization overhead under hot loop — a `bytes.Buffer` or `io.PipeWriter` with larger buffering would amortize this; (b) missing `bufio.Writer` wrapping around the pipe writer side, causing one `Write` syscall per multipart chunk boundary.

Recommended next steps (separate task):
- Wrap the `io.PipeWriter` with a `bufio.Writer` (e.g., 256 KB buffer) to reduce write syscalls.
- Use a `sync.Pool`-backed `[]byte` slice for the chunk read loop on the server side to collapse allocs/op.
- Re-run benchstat after fix to verify ns/op delta returns to ≤ +10% and allocs/op < 50.
