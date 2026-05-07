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
