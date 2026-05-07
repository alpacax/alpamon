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

var benchSizes = []int{1 << 20, 2 << 20, 3 << 20, 10 << 20, 100 << 20}

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
				body, _, err := buildMultipartStream(src, "f.bin", false, int64(size))
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
				body, ct, err := buildMultipartStream(src, filepath.Base(path), false, int64(size))
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
					return
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
