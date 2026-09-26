package updater

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
)

// signatureSuffix names the detached signature published next to the
// checksums file when the server does not give its URL.
const signatureSuffix = ".sig"

// PinnedRequest is a server-chosen upgrade target. Only TargetVersion is
// required; every URL defaults to the release layout under the base URL.
type PinnedRequest struct {
	TargetVersion  string
	ArtifactURL    string
	ArtifactDigest string // SHA-256, bare hex or "sha256:"-prefixed; optional
	ChecksumsURL   string
	SignatureURL   string
}

// NormalizeTag returns version as a "v"-prefixed release tag, or an error when
// it is not one.
func NormalizeTag(version string) (string, error) {
	tag := strings.TrimSpace(version)
	if tag != "" && !strings.HasPrefix(tag, "v") {
		tag = "v" + tag
	}
	if !versionRe.MatchString(tag) {
		return "", fmt.Errorf("invalid version format: %q", version)
	}
	return tag, nil
}

// pinnedSources is a PinnedRequest resolved against the release layout.
type pinnedSources struct {
	tag          string
	archiveName  string
	artifactURL  string
	checksumsURL string
	signatureURL string
	digest       string
}

func resolvePinned(req PinnedRequest, opts Options) (*pinnedSources, error) {
	tag, err := NormalizeTag(req.TargetVersion)
	if err != nil {
		return nil, err
	}
	digest, err := normalizeDigest(req.ArtifactDigest)
	if err != nil {
		return nil, err
	}
	base := opts.baseURL()
	src := &pinnedSources{
		tag:          tag,
		archiveName:  archiveFilename(tag),
		artifactURL:  req.ArtifactURL,
		checksumsURL: req.ChecksumsURL,
		signatureURL: req.SignatureURL,
		digest:       digest,
	}
	if src.artifactURL == "" {
		src.artifactURL = fmt.Sprintf("%s/%s/%s", base, tag, src.archiveName)
	}
	if src.checksumsURL == "" {
		src.checksumsURL = checksumURL(base, tag)
	}
	if src.signatureURL == "" {
		src.signatureURL = src.checksumsURL + signatureSuffix
	}

	for _, raw := range []string{src.artifactURL, src.checksumsURL, src.signatureURL} {
		if err := checkSourceURL(raw, opts.allowHTTP); err != nil {
			return nil, err
		}
	}
	// The signed checksums line is looked up by the archive name for this
	// OS and architecture, so an artifact URL naming anything else would be
	// checked against the wrong line.
	u, _ := url.Parse(src.artifactURL)
	if path.Base(u.Path) != src.archiveName {
		return nil, fmt.Errorf("artifact URL does not name %s, the archive for this platform", src.archiveName)
	}
	return src, nil
}

func checkSourceURL(raw string, allowHTTP bool) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return fmt.Errorf("invalid download URL %q", raw)
	}
	if u.Scheme == "https" || (allowHTTP && u.Scheme == "http") {
		return nil
	}
	return fmt.Errorf("download URL %q must use https", raw)
}

func downloadBytes(ctx context.Context, rawURL string, limit int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d from %s", resp.StatusCode, rawURL)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, fmt.Errorf("failed to read %s: %w", rawURL, err)
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%s exceeds the %d byte limit", rawURL, limit)
	}
	return data, nil
}

// preparePinned downloads and verifies the pinned artifact and extracts its
// binary into tempDir. Nothing outside tempDir is written.
func preparePinned(ctx context.Context, src *pinnedSources, opts Options, tempDir string) (string, error) {
	keyring := opts.Keyring
	if keyring == nil {
		var err error
		if keyring, err = ReleaseKeyring(); err != nil {
			return "", Classify(ClassSignatureInvalid, fmt.Errorf("compiled release key bundle is unreadable: %w", err))
		}
	}
	// Refuse before downloading anything: without a key nothing can pass.
	if keyring.Len() == 0 {
		return "", Classify(ClassSignatureInvalid, ErrNoTrustedKeys)
	}

	archivePath := filepath.Join(tempDir, src.archiveName)
	log.Debug().Str("url", src.artifactURL).Msg("Downloading pinned release archive.")
	if err := downloadFile(ctx, src.artifactURL, archivePath); err != nil {
		return "", Classify(ClassDownloadFailed, fmt.Errorf("failed to download artifact: %w", err))
	}
	checksums, err := downloadBytes(ctx, src.checksumsURL, maxChecksumFileSize)
	if err != nil {
		return "", Classify(ClassDownloadFailed, fmt.Errorf("failed to download checksums: %w", err))
	}
	signature, err := downloadBytes(ctx, src.signatureURL, maxSignatureSize)
	if err != nil {
		return "", Classify(ClassDownloadFailed, fmt.Errorf("failed to download checksums signature: %w", err))
	}

	if err := verifyPinnedArtifact(keyring, archivePath, src.archiveName, checksums, signature, src.digest); err != nil {
		return "", err
	}
	log.Debug().Msg("Checksums signature and artifact digest verified.")

	extractedPath := filepath.Join(tempDir, binaryName)
	if err := extractBinary(archivePath, extractedPath); err != nil {
		return "", Classify(ClassUnknown, fmt.Errorf("failed to extract binary: %w", err))
	}
	if err := validateBinaryFormat(extractedPath); err != nil {
		return "", Classify(ClassUnknown, fmt.Errorf("binary format validation failed: %w", err))
	}
	return extractedPath, nil
}

// PinnedSelfUpdate replaces the running binary with the release the server
// pinned. Unlike SelfUpdate it verifies a detached signature over the
// checksums file against the compiled-in keyring before anything is written,
// and refuses outright when that keyring is empty. Every error it returns
// carries an ErrorClass.
func PinnedSelfUpdate(ctx context.Context, req PinnedRequest, opts Options) error {
	if !selfUpdateInFlight.CompareAndSwap(false, true) {
		return ErrSelfUpdateInProgress
	}
	success := false
	defer func() {
		if !success {
			selfUpdateInFlight.Store(false)
		}
	}()

	src, err := resolvePinned(req, opts)
	if err != nil {
		return Classify(ClassUnknown, err)
	}
	if err := ensureSelfRestartable(); err != nil {
		return Classify(ClassUnknown, err)
	}
	CleanupStaleOld()

	currentPath, err := currentBinaryPath(opts)
	if err != nil {
		return Classify(ClassUnknown, err)
	}

	tempDir, err := os.MkdirTemp("", "alpamon-update-")
	if err != nil {
		return Classify(ClassUnknown, fmt.Errorf("failed to create temp directory: %w", err))
	}
	defer func() { _ = os.RemoveAll(tempDir) }()

	log.Info().Str("version", src.tag).Msg("Starting pinned self-update.")
	extractedPath, err := preparePinned(ctx, src, opts, tempDir)
	if err != nil {
		return err
	}

	if err := replaceBinary(extractedPath, currentPath); err != nil {
		return Classify(ClassSwapFailed, fmt.Errorf("failed to replace binary: %w", err))
	}

	log.Info().Str("version", src.tag).Msg("Pinned self-update completed.")
	success = true
	return nil
}

func currentBinaryPath(opts Options) (string, error) {
	if opts.binaryPath != "" {
		return opts.binaryPath, nil
	}
	p, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("failed to determine current binary path: %w", err)
	}
	p, err = filepath.EvalSymlinks(p)
	if err != nil {
		return "", fmt.Errorf("failed to resolve binary symlink: %w", err)
	}
	return p, nil
}
