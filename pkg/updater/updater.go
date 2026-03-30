package updater

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"context"
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
	maxChecksumFileSize   = 1 * 1024 * 1024 // 1 MB
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
func SelfUpdate(ctx context.Context, latestVersion string, opts Options) error {
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
	if err := downloadFile(ctx, archiveURL, archivePath); err != nil {
		return fmt.Errorf("failed to download release: %w", err)
	}

	// 2. Verify checksum
	// TODO(security): Add GPG or cosign signature verification. Currently only
	// HTTPS + SHA256 checksum is verified, which does not protect against
	// compromised GitHub releases. Since alpamon runs as root, a tampered binary
	// grants full server access.
	checksumFileURL := checksumURL(baseURL, latestVersion)
	if err := verifyChecksum(ctx, archivePath, archiveName, checksumFileURL); err != nil {
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

func downloadFile(ctx context.Context, url, destPath string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	client := &http.Client{Timeout: downloadTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("HTTP request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status %d from %s", resp.StatusCode, url)
	}

	if resp.ContentLength > 0 && resp.ContentLength > maxArchiveSize {
		return fmt.Errorf("download size %d exceeds maximum allowed %d bytes", resp.ContentLength, maxArchiveSize)
	}

	out, err := os.OpenFile(destPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}

	var writeErr error
	defer func() {
		_ = out.Close()
		if writeErr != nil {
			_ = os.Remove(destPath)
		}
	}()

	// Read maxArchiveSize+1 to detect oversize responses without Content-Length
	lr := &io.LimitedReader{R: resp.Body, N: maxArchiveSize + 1}
	written, err := io.Copy(out, lr)
	if err != nil {
		writeErr = fmt.Errorf("failed to write file: %w", err)
		return writeErr
	}
	if written > maxArchiveSize {
		writeErr = fmt.Errorf("downloaded file too large: limit is %d bytes", maxArchiveSize)
		return writeErr
	}

	return nil
}

func verifyChecksum(ctx context.Context, archivePath, archiveName, checksumFileURL string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, checksumFileURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create checksum request: %w", err)
	}
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to download checksums: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("checksums file returned status %d", resp.StatusCode)
	}

	// Parse checksums: "{hash}  {filename}"
	var expectedHash string
	scanner := bufio.NewScanner(io.LimitReader(resp.Body, maxChecksumFileSize))
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
			if hdr.Size > maxExtractSize {
				return fmt.Errorf("binary size %d exceeds maximum allowed %d bytes", hdr.Size, maxExtractSize)
			}

			out, err := os.OpenFile(destPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
			if err != nil {
				return fmt.Errorf("failed to create output file: %w", err)
			}

			written, err := io.Copy(out, io.LimitReader(tr, maxExtractSize))
			if err != nil {
				_ = out.Close()
				return fmt.Errorf("failed to extract binary: %w", err)
			}
			if written != hdr.Size {
				_ = out.Close()
				return fmt.Errorf("extracted size %d does not match declared size %d", written, hdr.Size)
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
	default:
		return fmt.Errorf("binary format validation not supported on platform %q", runtime.GOOS)
	}

	return nil
}

// machoMagics contains all recognized Mach-O magic byte sequences.
var machoMagics = [][4]byte{
	{0xFE, 0xED, 0xFA, 0xCE}, // Mach-O 32-bit big-endian
	{0xFE, 0xED, 0xFA, 0xCF}, // Mach-O 64-bit big-endian
	{0xCE, 0xFA, 0xED, 0xFE}, // Mach-O 32-bit little-endian
	{0xCF, 0xFA, 0xED, 0xFE}, // Mach-O 64-bit little-endian
	{0xCA, 0xFE, 0xBA, 0xBE}, // Universal binary (fat)
	{0xBE, 0xBA, 0xFE, 0xCA}, // Universal binary (fat, byte-swapped)
	{0xCA, 0xFE, 0xBA, 0xBF}, // Universal binary 64-bit (fat)
	{0xBF, 0xBA, 0xFE, 0xCA}, // Universal binary 64-bit (fat, byte-swapped)
}

func isMachO(magic []byte) bool {
	if len(magic) < 4 {
		return false
	}
	m := [4]byte{magic[0], magic[1], magic[2], magic[3]}
	for _, v := range machoMagics {
		if m == v {
			return true
		}
	}
	return false
}

func replaceBinary(newPath, currentPath string) error {
	info, err := os.Stat(currentPath)
	if err != nil {
		return fmt.Errorf("failed to stat current binary: %w", err)
	}

	// Backup current binary for rollback on failure
	backupPath := currentPath + ".bak"
	if err := copyFile(currentPath, backupPath, info.Mode()); err != nil {
		return fmt.Errorf("failed to backup current binary: %w", err)
	}

	// Stage new binary next to current (same filesystem for atomic rename)
	stagePath := currentPath + ".new"
	if err := copyFile(newPath, stagePath, info.Mode()); err != nil {
		return fmt.Errorf("failed to stage new binary: %w", err)
	}
	defer func() { _ = os.Remove(stagePath) }()

	// Atomic replace
	if err := os.Rename(stagePath, currentPath); err != nil {
		return fmt.Errorf("failed to rename binary: %w", err)
	}

	// Replace succeeded — remove backup
	_ = os.Remove(backupPath)
	log.Debug().Msg("Binary replaced successfully, backup removed.")
	return nil
}

// copyFile copies src to dst with the given permissions.
func copyFile(src, dst string, perm os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()

	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, perm)
	if err != nil {
		return err
	}

	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}
