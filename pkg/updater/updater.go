package updater

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
)

const (
	defaultReleaseBaseURL = "https://github.com/alpacax/alpamon/releases/download"
	downloadTimeout       = 5 * time.Minute
	maxArchiveSize        = 100 * 1024 * 1024 // 100 MB
	maxExtractSize        = 500 * 1024 * 1024 // 500 MB
	maxTarEntries         = 100
	binaryName            = "alpamon"
)

var versionRe = regexp.MustCompile(`^v\d+\.\d+\.\d+(-[\w.]+)?$`)

// Options configures the self-update behavior. Use defaults for production.
type Options struct {
	BaseURL string // Override release base URL (for testing)
}

func (o Options) baseURL() string {
	if o.BaseURL != "" {
		return o.BaseURL
	}
	return defaultReleaseBaseURL
}

// SelfUpdate downloads the latest binary from GitHub Releases,
// verifies its checksum, and replaces the current binary.
func SelfUpdate(latestVersion string, opts Options) error {
	if !versionRe.MatchString(latestVersion) {
		return fmt.Errorf("invalid version format: %q", latestVersion)
	}

	log.Info().Str("version", latestVersion).Msg("Starting self-update.")

	currentPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to determine current binary path: %w", err)
	}
	currentPath, err = filepath.EvalSymlinks(currentPath)
	if err != nil {
		return fmt.Errorf("failed to resolve binary symlink: %w", err)
	}

	tempDir, err := os.MkdirTemp("", "alpamon-update-")
	if err != nil {
		return fmt.Errorf("failed to create temp directory: %w", err)
	}
	defer func() { _ = os.RemoveAll(tempDir) }()

	baseURL := opts.baseURL()

	// 1. Download archive
	archiveName := archiveFilename(latestVersion)
	archivePath := filepath.Join(tempDir, archiveName)
	archiveURL := fmt.Sprintf("%s/%s/%s", baseURL, latestVersion, archiveName)

	log.Debug().Str("url", archiveURL).Msg("Downloading release archive.")
	if err := downloadFile(archiveURL, archivePath); err != nil {
		return fmt.Errorf("failed to download release: %w", err)
	}

	// 2. Verify checksum
	checksumFileURL := checksumURL(baseURL, latestVersion)
	if err := verifyChecksum(archivePath, archiveName, checksumFileURL); err != nil {
		return fmt.Errorf("checksum verification failed: %w", err)
	}
	log.Debug().Msg("Checksum verified.")

	// 3. Extract binary
	extractedPath := filepath.Join(tempDir, binaryName)
	if err := extractBinary(archivePath, extractedPath); err != nil {
		return fmt.Errorf("failed to extract binary: %w", err)
	}

	// 4. Validate binary format (architecture check without execution)
	if err := validateBinaryFormat(extractedPath); err != nil {
		return fmt.Errorf("binary format validation failed: %w", err)
	}
	log.Debug().Msg("Binary format validated.")

	// 5. Replace current binary atomically
	if err := replaceBinary(extractedPath, currentPath); err != nil {
		return fmt.Errorf("failed to replace binary: %w", err)
	}

	log.Info().Str("version", latestVersion).Msg("Self-update completed.")
	return nil
}

func archiveFilename(version string) string {
	v := strings.TrimPrefix(version, "v")
	return fmt.Sprintf("%s-%s-%s-%s.tar.gz", binaryName, v, runtime.GOOS, runtime.GOARCH)
}

func checksumURL(baseURL, version string) string {
	v := strings.TrimPrefix(version, "v")
	return fmt.Sprintf("%s/%s/%s-%s-checksums.sha256", baseURL, version, binaryName, v)
}

func downloadFile(url, destPath string) error {
	client := &http.Client{Timeout: downloadTimeout}
	resp, err := client.Get(url)
	if err != nil {
		return fmt.Errorf("HTTP request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status %d from %s", resp.StatusCode, url)
	}

	out, err := os.OpenFile(destPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}

	if _, err := io.Copy(out, io.LimitReader(resp.Body, maxArchiveSize)); err != nil {
		_ = out.Close()
		return fmt.Errorf("failed to write file: %w", err)
	}
	if err := out.Close(); err != nil {
		return fmt.Errorf("failed to flush downloaded file: %w", err)
	}

	return nil
}

func verifyChecksum(archivePath, archiveName, checksumFileURL string) error {
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(checksumFileURL)
	if err != nil {
		return fmt.Errorf("failed to download checksums: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("checksums file returned status %d", resp.StatusCode)
	}

	// Parse checksums: "{hash}  {filename}"
	var expectedHash string
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) == 2 && fields[1] == archiveName {
			expectedHash = fields[0]
			break
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("failed to read checksums: %w", err)
	}
	if expectedHash == "" {
		return fmt.Errorf("checksum not found for %s", archiveName)
	}

	// Compute actual hash
	f, err := os.Open(archivePath)
	if err != nil {
		return fmt.Errorf("failed to open archive for hashing: %w", err)
	}
	defer func() { _ = f.Close() }()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return fmt.Errorf("failed to hash archive: %w", err)
	}
	actualHash := hex.EncodeToString(h.Sum(nil))

	if actualHash != expectedHash {
		return fmt.Errorf("checksum mismatch: expected %s, got %s", expectedHash, actualHash)
	}

	return nil
}

func extractBinary(archivePath, destPath string) error {
	f, err := os.Open(archivePath)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	gz, err := gzip.NewReader(f)
	if err != nil {
		return fmt.Errorf("failed to open gzip: %w", err)
	}
	defer func() { _ = gz.Close() }()

	tr := tar.NewReader(gz)
	entries := 0
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("failed to read tar: %w", err)
		}

		entries++
		if entries > maxTarEntries {
			return fmt.Errorf("archive contains too many entries (max %d)", maxTarEntries)
		}

		// Look for the alpamon binary (may be at root or in a subdirectory)
		if filepath.Base(hdr.Name) == binaryName && hdr.Typeflag == tar.TypeReg {
			out, err := os.OpenFile(destPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
			if err != nil {
				return fmt.Errorf("failed to create output file: %w", err)
			}

			if _, err := io.Copy(out, io.LimitReader(tr, maxExtractSize)); err != nil {
				_ = out.Close()
				return fmt.Errorf("failed to extract binary: %w", err)
			}
			if err := out.Close(); err != nil {
				return fmt.Errorf("failed to flush extracted binary: %w", err)
			}
			return nil
		}
	}

	return fmt.Errorf("binary %q not found in archive", binaryName)
}

// validateBinaryFormat checks that the extracted file is a valid executable
// for the current platform by inspecting magic bytes. This avoids executing
// an unverified binary.
func validateBinaryFormat(binaryPath string) error {
	f, err := os.Open(binaryPath)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	magic := make([]byte, 4)
	if _, err := io.ReadFull(f, magic); err != nil {
		return fmt.Errorf("failed to read binary header: %w", err)
	}

	switch runtime.GOOS {
	case "darwin":
		// Mach-O: 0xFEEDFACE (32-bit), 0xFEEDFACF (64-bit), 0xCAFEBABE (universal)
		if !isMachO(magic) {
			return fmt.Errorf("not a valid Mach-O binary (magic: %x)", magic)
		}
	case "linux":
		// ELF: 0x7F 'E' 'L' 'F'
		if magic[0] != 0x7f || magic[1] != 'E' || magic[2] != 'L' || magic[3] != 'F' {
			return fmt.Errorf("not a valid ELF binary (magic: %x)", magic)
		}
	}

	return nil
}

func isMachO(magic []byte) bool {
	if len(magic) < 4 {
		return false
	}
	// Big-endian magic bytes
	return (magic[0] == 0xFE && magic[1] == 0xED && magic[2] == 0xFA && (magic[3] == 0xCE || magic[3] == 0xCF)) ||
		// Little-endian magic bytes
		((magic[0] == 0xCE || magic[0] == 0xCF) && magic[1] == 0xFA && magic[2] == 0xED && magic[3] == 0xFE) ||
		// Universal binary (fat)
		(magic[0] == 0xCA && magic[1] == 0xFE && magic[2] == 0xBA && magic[3] == 0xBE)
}

func replaceBinary(newPath, currentPath string) error {
	info, err := os.Stat(currentPath)
	if err != nil {
		return fmt.Errorf("failed to stat current binary: %w", err)
	}

	// Stage new binary next to current (same filesystem for atomic rename)
	stagePath := currentPath + ".new"
	defer func() { _ = os.Remove(stagePath) }()

	src, err := os.Open(newPath)
	if err != nil {
		return fmt.Errorf("failed to open new binary: %w", err)
	}
	defer func() { _ = src.Close() }()

	dst, err := os.OpenFile(stagePath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, info.Mode())
	if err != nil {
		return fmt.Errorf("failed to create staged binary: %w", err)
	}

	if _, err := io.Copy(dst, src); err != nil {
		_ = dst.Close()
		return fmt.Errorf("failed to copy binary: %w", err)
	}
	if err := dst.Close(); err != nil {
		return fmt.Errorf("failed to close staged binary: %w", err)
	}

	// Atomic replace
	if err := os.Rename(stagePath, currentPath); err != nil {
		return fmt.Errorf("failed to rename binary: %w", err)
	}

	return nil
}
