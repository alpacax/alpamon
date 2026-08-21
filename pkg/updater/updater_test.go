package updater

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// assertGone fails unless path is absent, which os.Stat reports as
// os.ErrNotExist. assert.NoFileExists is the shorter spelling but it treats a
// directory at path, and any other Lstat error, as absence; both callers here
// are proving that a cleanup step ran, so nothing but a missing path passes.
func assertGone(t *testing.T, path, msg string) {
	t.Helper()
	_, err := os.Stat(path)
	assert.ErrorIs(t, err, os.ErrNotExist, msg)
}

// createTestArchive creates a tar.gz archive containing a fake alpamon binary.
func createTestArchive(t *testing.T, binaryContent []byte) []byte {
	t.Helper()
	return createTestArchiveNamed(t, binaryName, binaryContent)
}

// createTestArchiveNamed creates a tar.gz archive containing a single
// file with the given name. Used to test both Unix-style "alpamon"
// and Windows-style "alpamon.exe" archive entries.
func createTestArchiveNamed(t *testing.T, entryName string, binaryContent []byte) []byte {
	t.Helper()
	var archive bytes.Buffer
	gw := gzip.NewWriter(&archive)
	tw := tar.NewWriter(gw)

	require.NoError(t, tw.WriteHeader(&tar.Header{
		Name: entryName,
		Mode: 0755,
		Size: int64(len(binaryContent)),
	}))
	_, err := tw.Write(binaryContent)
	require.NoError(t, err)

	// Both Close calls flush, so a failure here means a truncated archive.
	require.NoError(t, tw.Close())
	require.NoError(t, gw.Close())
	return archive.Bytes()
}

func sha256Hex(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

func TestArchiveFilename(t *testing.T) {
	assert.Equal(t, fmt.Sprintf("alpamon-1.2.3-%s-%s.tar.gz", runtime.GOOS, runtime.GOARCH), archiveFilename("v1.2.3"))
}

func TestChecksumURL(t *testing.T) {
	assert.Equal(t,
		"https://github.com/alpacax/alpamon/releases/download/v1.2.3/alpamon-1.2.3-checksums.sha256",
		checksumURL(defaultReleaseBaseURL, "v1.2.3"))
}

func TestDownloadFile(t *testing.T) {
	content := []byte("test binary content")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(content)
	}))
	defer server.Close()

	destPath := filepath.Join(t.TempDir(), "downloaded")
	require.NoError(t, downloadFile(context.Background(), server.URL, destPath))

	got, err := os.ReadFile(destPath)
	require.NoError(t, err)
	assert.Equal(t, string(content), string(got))

	// Verify file permissions are restrictive (Unix only: Windows doesn't enforce Unix perms)
	if runtime.GOOS != "windows" {
		info, err := os.Stat(destPath)
		require.NoError(t, err)
		assert.Zero(t, info.Mode().Perm()&0077,
			"downloaded file should not be group/world accessible, got %o", info.Mode().Perm())
	}
}

func TestDownloadFile_NotFound(t *testing.T) {
	server := httptest.NewServer(http.NotFoundHandler())
	defer server.Close()

	destPath := filepath.Join(t.TempDir(), "downloaded")
	err := downloadFile(context.Background(), server.URL, destPath)
	assert.ErrorContains(t, err, "404")
}

func TestDownloadFile_Oversize(t *testing.T) {
	// Server streams more than maxArchiveSize without Content-Length
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Write maxArchiveSize+1 bytes in chunks to avoid setting Content-Length
		chunk := make([]byte, 32*1024)
		remaining := int64(maxArchiveSize) + 1
		for remaining > 0 {
			n := min(int64(len(chunk)), remaining)
			_, _ = w.Write(chunk[:n])
			remaining -= n
		}
	}))
	defer server.Close()

	destPath := filepath.Join(t.TempDir(), "downloaded")
	err := downloadFile(context.Background(), server.URL, destPath)
	assert.ErrorContains(t, err, "too large")
}

func TestDownloadFile_ContextCancelled(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Slow server that never finishes
		select {
		case <-r.Context().Done():
		case <-time.After(10 * time.Second):
		}
	}))
	defer server.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	destPath := filepath.Join(t.TempDir(), "downloaded")
	assert.Error(t, downloadFile(ctx, server.URL, destPath), "expected error for cancelled context")
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

	archivePath := filepath.Join(t.TempDir(), archiveName)
	require.NoError(t, os.WriteFile(archivePath, archiveContent, 0644))

	err := verifyChecksum(context.Background(), archivePath, archiveName, server.URL+"/checksums.sha256")
	require.NoError(t, err)
}

func TestVerifyChecksum_Mismatch(t *testing.T) {
	archiveName := "alpamon-1.0.0-darwin-arm64.tar.gz"
	checksumBody := fmt.Sprintf("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef  %s\n", archiveName)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(checksumBody))
	}))
	defer server.Close()

	archivePath := filepath.Join(t.TempDir(), archiveName)
	require.NoError(t, os.WriteFile(archivePath, []byte("different content"), 0644))

	err := verifyChecksum(context.Background(), archivePath, archiveName, server.URL+"/checksums.sha256")
	assert.ErrorContains(t, err, "mismatch")
}

func TestExtractBinary(t *testing.T) {
	binaryContent := []byte("#!/bin/sh\necho hello")
	archive := createTestArchive(t, binaryContent)

	tempDir := t.TempDir()
	archivePath := filepath.Join(tempDir, "test.tar.gz")
	require.NoError(t, os.WriteFile(archivePath, archive, 0644))

	destPath := filepath.Join(tempDir, "extracted")
	require.NoError(t, extractBinary(archivePath, destPath))

	got, err := os.ReadFile(destPath)
	require.NoError(t, err)
	assert.Equal(t, string(binaryContent), string(got))

	info, err := os.Stat(destPath)
	require.NoError(t, err, "failed to stat extracted binary")
	if runtime.GOOS != "windows" {
		assert.NotZero(t, info.Mode()&0111, "extracted binary should be executable")
	}
}

func TestExtractBinary_WindowsExe(t *testing.T) {
	// goreleaser appends ".exe" to the binary name on Windows; the
	// extractor must recognise that entry too. Regression guard for
	// isAlpamonBinary.
	binaryContent := []byte("fake pe binary")
	archive := createTestArchiveNamed(t, "alpamon.exe", binaryContent)

	tempDir := t.TempDir()
	archivePath := filepath.Join(tempDir, "test.tar.gz")
	require.NoError(t, os.WriteFile(archivePath, archive, 0644))

	destPath := filepath.Join(tempDir, "extracted")
	require.NoError(t, extractBinary(archivePath, destPath), "extractBinary() must accept an alpamon.exe entry")

	got, err := os.ReadFile(destPath)
	require.NoError(t, err)
	assert.Equal(t, string(binaryContent), string(got))
}

func TestExtractBinary_NotFound(t *testing.T) {
	// Archive whose only entry is not the alpamon binary.
	archive := createTestArchiveNamed(t, "not-alpamon", []byte("hello"))

	tempDir := t.TempDir()
	archivePath := filepath.Join(tempDir, "test.tar.gz")
	require.NoError(t, os.WriteFile(archivePath, archive, 0644))

	err := extractBinary(archivePath, filepath.Join(tempDir, "extracted"))
	assert.ErrorContains(t, err, "not found in archive")
}

func TestReplaceBinary(t *testing.T) {
	tempDir := t.TempDir()

	currentPath := filepath.Join(tempDir, "alpamon")
	require.NoError(t, os.WriteFile(currentPath, []byte("old"), 0755))

	newPath := filepath.Join(tempDir, "alpamon-new")
	require.NoError(t, os.WriteFile(newPath, []byte("new"), 0755))

	require.NoError(t, replaceBinary(newPath, currentPath))

	got, err := os.ReadFile(currentPath)
	require.NoError(t, err)
	assert.Equal(t, "new", string(got))

	info, err := os.Stat(currentPath)
	require.NoError(t, err)
	if runtime.GOOS != "windows" {
		assert.Equal(t, os.FileMode(0755), info.Mode().Perm())
	}

	assertGone(t, currentPath+".new", "staged file should be cleaned up")

	// Backup should be removed on success
	assertGone(t, currentPath+".bak", "backup file should be cleaned up on success")
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
			err := SelfUpdate(context.Background(), tt.version, Options{})
			assert.ErrorContains(t, err, "invalid version format")
		})
	}
}

func TestSelfUpdate_AlreadyInProgress(t *testing.T) {
	require.True(t, selfUpdateInFlight.CompareAndSwap(false, true), "in-flight flag unexpectedly set before test")
	defer selfUpdateInFlight.Store(false)

	err := SelfUpdate(context.Background(), "v1.0.0", Options{})
	assert.ErrorIs(t, err, ErrSelfUpdateInProgress)
}

func TestSelfUpdate_InFlightFlagResets(t *testing.T) {
	// A failed run (invalid version) must clear the flag for the next call.
	require.Error(t, SelfUpdate(context.Background(), "not-a-version", Options{}), "expected error for invalid version")
	assert.False(t, selfUpdateInFlight.Load(), "in-flight flag not reset after failed SelfUpdate returned")
}

func TestReleaseSelfUpdateLatch(t *testing.T) {
	require.True(t, selfUpdateInFlight.CompareAndSwap(false, true), "in-flight flag unexpectedly set before test")
	defer selfUpdateInFlight.Store(false)

	ReleaseSelfUpdateLatch()
	assert.False(t, selfUpdateInFlight.Load(), "ReleaseSelfUpdateLatch did not clear the latch")
}

func TestIsMachO(t *testing.T) {
	tests := []struct {
		name  string
		magic []byte
		want  bool
	}{
		{"big-endian 32-bit", []byte{0xFE, 0xED, 0xFA, 0xCE}, true},
		{"big-endian 64-bit", []byte{0xFE, 0xED, 0xFA, 0xCF}, true},
		{"little-endian 32-bit", []byte{0xCE, 0xFA, 0xED, 0xFE}, true},
		{"little-endian 64-bit", []byte{0xCF, 0xFA, 0xED, 0xFE}, true},
		{"universal fat", []byte{0xCA, 0xFE, 0xBA, 0xBE}, true},
		{"universal fat swapped", []byte{0xBE, 0xBA, 0xFE, 0xCA}, true},
		{"universal fat 64", []byte{0xCA, 0xFE, 0xBA, 0xBF}, true},
		{"universal fat 64 swapped", []byte{0xBF, 0xBA, 0xFE, 0xCA}, true},
		{"invalid", []byte{0x00, 0x00, 0x00, 0x00}, false},
		{"too short", []byte{0xFE, 0xED}, false},
		{"nil", nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, isMachO(tt.magic), "magic %x", tt.magic)
		})
	}
}

func TestValidateBinaryFormat(t *testing.T) {
	tempDir := t.TempDir()

	// Test with invalid file
	invalidPath := filepath.Join(tempDir, "invalid")
	require.NoError(t, os.WriteFile(invalidPath, []byte("not a binary"), 0755))
	assert.Error(t, validateBinaryFormat(invalidPath), "expected error for invalid binary format")

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
	require.NoError(t, os.WriteFile(validPath, content, 0755))
	assert.NoError(t, validateBinaryFormat(validPath), "expected valid binary format")
}
