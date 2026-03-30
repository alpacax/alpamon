package updater

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// createTestArchive creates a tar.gz archive containing a fake alpamon binary.
func createTestArchive(t *testing.T, binaryContent []byte) []byte {
	t.Helper()
	tmpFile, err := os.CreateTemp("", "test-archive-*.tar.gz")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = tmpFile.Close()
		_ = os.Remove(tmpFile.Name())
	}()

	gw := gzip.NewWriter(tmpFile)
	tw := tar.NewWriter(gw)

	hdr := &tar.Header{
		Name: binaryName,
		Mode: 0755,
		Size: int64(len(binaryContent)),
	}
	if err := tw.WriteHeader(hdr); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(binaryContent); err != nil {
		t.Fatal(err)
	}

	_ = tw.Close()
	_ = gw.Close()

	data, err := os.ReadFile(tmpFile.Name())
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func sha256Hex(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

func TestArchiveFilename(t *testing.T) {
	got := archiveFilename("v1.2.3")
	expected := fmt.Sprintf("alpamon-1.2.3-%s-%s.tar.gz", runtime.GOOS, runtime.GOARCH)
	if got != expected {
		t.Errorf("archiveFilename(v1.2.3) = %q, want %q", got, expected)
	}
}

func TestChecksumURL(t *testing.T) {
	got := checksumURL(defaultReleaseBaseURL, "v1.2.3")
	expected := "https://github.com/alpacax/alpamon/releases/download/v1.2.3/alpamon-1.2.3-checksums.sha256"
	if got != expected {
		t.Errorf("checksumURL() = %q, want %q", got, expected)
	}
}

func TestDownloadFile(t *testing.T) {
	content := []byte("test binary content")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(content)
	}))
	defer server.Close()

	destPath := filepath.Join(t.TempDir(), "downloaded")
	if err := downloadFile(server.URL, destPath); err != nil {
		t.Fatalf("downloadFile() error: %v", err)
	}

	got, err := os.ReadFile(destPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(content) {
		t.Errorf("downloaded content = %q, want %q", got, content)
	}

	// Verify file permissions are restrictive
	info, err := os.Stat(destPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0077 != 0 {
		t.Errorf("downloaded file should not be group/world accessible, got %o", info.Mode().Perm())
	}
}

func TestDownloadFile_NotFound(t *testing.T) {
	server := httptest.NewServer(http.NotFoundHandler())
	defer server.Close()

	destPath := filepath.Join(t.TempDir(), "downloaded")
	err := downloadFile(server.URL, destPath)
	if err == nil {
		t.Fatal("expected error for 404 response")
	}
	if !strings.Contains(err.Error(), "404") {
		t.Errorf("error should mention 404, got: %v", err)
	}
}

func TestVerifyChecksum(t *testing.T) {
	archiveContent := []byte("fake archive content")
	hash := sha256Hex(archiveContent)
	archiveName := "alpamon-1.0.0-darwin-arm64.tar.gz"

	checksumBody := fmt.Sprintf("%s  %s\n%s  other-file.tar.gz\n", hash, archiveName, "deadbeef")

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(checksumBody))
	}))
	defer server.Close()

	tempDir := t.TempDir()
	archivePath := filepath.Join(tempDir, archiveName)
	if err := os.WriteFile(archivePath, archiveContent, 0644); err != nil {
		t.Fatal(err)
	}

	err := verifyChecksum(archivePath, archiveName, server.URL+"/checksums.sha256")
	if err != nil {
		t.Fatalf("verifyChecksum() error: %v", err)
	}
}

func TestVerifyChecksum_Mismatch(t *testing.T) {
	archiveName := "alpamon-1.0.0-darwin-arm64.tar.gz"
	checksumBody := fmt.Sprintf("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef  %s\n", archiveName)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(checksumBody))
	}))
	defer server.Close()

	tempDir := t.TempDir()
	archivePath := filepath.Join(tempDir, archiveName)
	if err := os.WriteFile(archivePath, []byte("different content"), 0644); err != nil {
		t.Fatal(err)
	}

	err := verifyChecksum(archivePath, archiveName, server.URL+"/checksums.sha256")
	if err == nil {
		t.Fatal("expected checksum mismatch error")
	}
	if !strings.Contains(err.Error(), "mismatch") {
		t.Errorf("error should mention mismatch, got: %v", err)
	}
}

func TestExtractBinary(t *testing.T) {
	binaryContent := []byte("#!/bin/sh\necho hello")
	archive := createTestArchive(t, binaryContent)

	tempDir := t.TempDir()
	archivePath := filepath.Join(tempDir, "test.tar.gz")
	if err := os.WriteFile(archivePath, archive, 0644); err != nil {
		t.Fatal(err)
	}

	destPath := filepath.Join(tempDir, "extracted")
	if err := extractBinary(archivePath, destPath); err != nil {
		t.Fatalf("extractBinary() error: %v", err)
	}

	got, err := os.ReadFile(destPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(binaryContent) {
		t.Errorf("extracted content = %q, want %q", got, binaryContent)
	}

	info, statErr := os.Stat(destPath)
	if statErr != nil {
		t.Fatalf("failed to stat extracted binary: %v", statErr)
	}
	if info.Mode()&0111 == 0 {
		t.Error("extracted binary should be executable")
	}
}

func TestExtractBinary_NotFound(t *testing.T) {
	// Archive with a different filename
	tmpFile, err := os.CreateTemp("", "test-archive-*.tar.gz")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Remove(tmpFile.Name()) }()

	gw := gzip.NewWriter(tmpFile)
	tw := tar.NewWriter(gw)
	hdr := &tar.Header{Name: "not-alpamon", Mode: 0755, Size: 5}
	_ = tw.WriteHeader(hdr)
	_, _ = tw.Write([]byte("hello"))
	_ = tw.Close()
	_ = gw.Close()
	_ = tmpFile.Close()

	destPath := filepath.Join(t.TempDir(), "extracted")
	err = extractBinary(tmpFile.Name(), destPath)
	if err == nil {
		t.Fatal("expected error when binary not found in archive")
	}
	if !strings.Contains(err.Error(), "not found in archive") {
		t.Errorf("error should mention not found, got: %v", err)
	}
}

func TestReplaceBinary(t *testing.T) {
	tempDir := t.TempDir()

	currentPath := filepath.Join(tempDir, "alpamon")
	if err := os.WriteFile(currentPath, []byte("old"), 0755); err != nil {
		t.Fatal(err)
	}

	newPath := filepath.Join(tempDir, "alpamon-new")
	if err := os.WriteFile(newPath, []byte("new"), 0755); err != nil {
		t.Fatal(err)
	}

	if err := replaceBinary(newPath, currentPath); err != nil {
		t.Fatalf("replaceBinary() error: %v", err)
	}

	got, err := os.ReadFile(currentPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "new" {
		t.Errorf("binary content = %q, want %q", got, "new")
	}

	info, err := os.Stat(currentPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0755 {
		t.Errorf("permissions = %o, want 0755", info.Mode().Perm())
	}

	if _, err := os.Stat(currentPath + ".new"); !os.IsNotExist(err) {
		t.Error("staged file should be cleaned up")
	}
}

func TestSelfUpdate_InvalidVersion(t *testing.T) {
	tests := []struct {
		name    string
		version string
	}{
		{"path traversal", "../../../etc/passwd"},
		{"empty", ""},
		{"no v prefix", "1.2.3"},
		{"shell injection", "v1.0.0; rm -rf /"},
		{"url encoded", "v1.0.0%2F..%2F.."},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := SelfUpdate(tt.version, Options{})
			if err == nil {
				t.Fatal("expected error for invalid version")
			}
			if !strings.Contains(err.Error(), "invalid version format") {
				t.Errorf("error should mention invalid version format, got: %v", err)
			}
		})
	}
}

func TestValidateBinaryFormat(t *testing.T) {
	tempDir := t.TempDir()

	// Test with invalid file
	invalidPath := filepath.Join(tempDir, "invalid")
	if err := os.WriteFile(invalidPath, []byte("not a binary"), 0755); err != nil {
		t.Fatal(err)
	}
	err := validateBinaryFormat(invalidPath)
	if err == nil {
		t.Error("expected error for invalid binary format")
	}

	// Test with valid binary for the current platform
	var magic []byte
	switch runtime.GOOS {
	case "linux":
		magic = []byte{0x7f, 'E', 'L', 'F'}
	case "darwin":
		magic = []byte{0xcf, 0xfa, 0xed, 0xfe} // 64-bit little-endian Mach-O
	default:
		t.Skipf("validateBinaryFormat not exercised for GOOS=%s", runtime.GOOS)
	}

	validPath := filepath.Join(tempDir, "valid")
	content := append(magic, []byte("dummy")...)
	if err := os.WriteFile(validPath, content, 0755); err != nil {
		t.Fatal(err)
	}
	if err := validateBinaryFormat(validPath); err != nil {
		t.Errorf("expected valid binary format, got error: %v", err)
	}
}
