package file

import (
	"bytes"
	"context"
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

// benchSizes spans the observed real-world distribution: KB-scale config files
// (most uploads), 1–100 MB midrange, and GB-scale cloud images. Sizes >= 500 MB
// are skipped under -short to keep CI fast.
var benchSizes = []int{
	1 << 10,   // 1 KB
	64 << 10,  // 64 KB
	1 << 20,   // 1 MB
	10 << 20,  // 10 MB
	100 << 20, // 100 MB
	500 << 20, // 500 MB
	1 << 30,   // 1 GB
}

// sizeLabel formats a byte count as a sub-benchmark name (e.g. 1KB, 64KB, 1MB, 1GB).
func sizeLabel(n int) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%dGB", n>>30)
	case n >= 1<<20:
		return fmt.Sprintf("%dMB", n>>20)
	case n >= 1<<10:
		return fmt.Sprintf("%dKB", n>>10)
	default:
		return fmt.Sprintf("%dB", n)
	}
}

// skipIfLargeShort skips bench sizes >= 500 MB when -short is set, so CI runs
// stay fast while local runs can sweep the full range.
func skipIfLargeShort(b *testing.B, size int) {
	b.Helper()
	if testing.Short() && size >= (500<<20) {
		b.Skipf("skip %s in -short mode", sizeLabel(size))
	}
}

// makeTempFile writes pseudo-random bytes to a temp file. Random content avoids transport-level compression.
func makeTempFile(b *testing.B, size int) string {
	b.Helper()
	f, err := os.CreateTemp(b.TempDir(), "bench-*.bin")
	if err != nil {
		b.Fatalf("CreateTemp: %v", err)
	}
	defer func() { _ = f.Close() }()
	if _, err := io.CopyN(f, rand.Reader, int64(size)); err != nil {
		b.Fatalf("CopyN: %v", err)
	}
	return f.Name()
}

// newSinkServer drains request bodies and returns 200 — used as the upload destination.
func newSinkServer(b *testing.B) *httptest.Server {
	b.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	b.Cleanup(srv.Close)
	return srv
}

// reportGC records GC count and pause delta as bench-only metrics.
func reportGC(b *testing.B, before, after runtime.MemStats) {
	b.Helper()
	b.ReportMetric(float64(after.NumGC-before.NumGC)/float64(b.N), "gc-count/op")
	b.ReportMetric(float64(after.PauseTotalNs-before.PauseTotalNs)/float64(b.N), "gc-pause-ns/op")
}

// BenchmarkUpload_MultipartBody measures multipart body construction in isolation.
func BenchmarkUpload_MultipartBody(b *testing.B) {
	for _, size := range benchSizes {
		b.Run(sizeLabel(size), func(b *testing.B) {
			skipIfLargeShort(b, size)
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
				body, _, _, err := buildMultipartStream(src, "f.bin", false, int64(size))
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

// BenchmarkUpload_E2E exercises the full upload pipeline against a loopback HTTP sink.
func BenchmarkUpload_E2E(b *testing.B) {
	for _, size := range benchSizes {
		b.Run(sizeLabel(size), func(b *testing.B) {
			skipIfLargeShort(b, size)
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
				body, ct, contentLength, err := buildMultipartStream(src, filepath.Base(path), false, int64(size))
				if err != nil {
					_ = src.Close()
					b.Fatal(err)
				}
				req, _ := http.NewRequest(http.MethodPost, srv.URL, body)
				req.ContentLength = contentLength
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
