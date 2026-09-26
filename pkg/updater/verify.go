package updater

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"

	"github.com/ProtonMail/go-crypto/openpgp"
)

const maxSignatureSize = 64 * 1024 // 64 KB

var sha256HexRe = regexp.MustCompile(`^[0-9a-f]{64}$`)

// verifySignedChecksums checks that signature is a valid detached OpenPGP
// signature over checksums by a key in keyring. Both ASCII-armored and binary
// signatures are accepted. An empty keyring is a refusal, never a pass.
func verifySignedChecksums(keyring *Keyring, checksums, signature []byte) error {
	if keyring.Len() == 0 {
		return Classify(ClassSignatureInvalid, ErrNoTrustedKeys)
	}
	var err error
	if bytes.HasPrefix(bytes.TrimSpace(signature), []byte("-----BEGIN PGP SIGNATURE-----")) {
		_, err = openpgp.CheckArmoredDetachedSignature(keyring.entities, bytes.NewReader(checksums), bytes.NewReader(signature), nil)
	} else {
		_, err = openpgp.CheckDetachedSignature(keyring.entities, bytes.NewReader(checksums), bytes.NewReader(signature), nil)
	}
	if err != nil {
		return Classify(ClassSignatureInvalid, fmt.Errorf("checksums signature did not verify: %w", err))
	}
	return nil
}

// lookupChecksum returns the SHA-256 the checksums file lists for name. A
// file that lists the name twice is rejected rather than trusting either line.
func lookupChecksum(checksums []byte, name string) (string, error) {
	var found string
	scanner := bufio.NewScanner(bytes.NewReader(checksums))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) != 2 {
			continue
		}
		// sha256sum marks binary mode with a leading "*" on the name.
		if strings.TrimPrefix(fields[1], "*") != name {
			continue
		}
		if found != "" {
			return "", Classify(ClassDigestMismatch, fmt.Errorf("checksums file lists %s more than once", name))
		}
		found = strings.ToLower(fields[0])
	}
	if err := scanner.Err(); err != nil {
		return "", Classify(ClassDigestMismatch, fmt.Errorf("failed to read checksums: %w", err))
	}
	if found == "" {
		return "", Classify(ClassDigestMismatch, fmt.Errorf("signed checksums file has no entry for %s", name))
	}
	if !sha256HexRe.MatchString(found) {
		return "", Classify(ClassDigestMismatch, fmt.Errorf("checksums entry for %s is not a SHA-256 digest", name))
	}
	return found, nil
}

// normalizeDigest accepts a bare hex SHA-256 or one prefixed "sha256:" and
// returns the lowercase hex form. An empty input stays empty.
func normalizeDigest(digest string) (string, error) {
	if digest == "" {
		return "", nil
	}
	d := strings.ToLower(strings.TrimSpace(digest))
	d = strings.TrimPrefix(d, "sha256:")
	if !sha256HexRe.MatchString(d) {
		return "", errors.New("artifact digest is not a SHA-256 hex digest")
	}
	return d, nil
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// verifyPinnedArtifact runs the checks in their fixed order: the signature
// over the checksums file first, then the artifact's digest against the signed
// line, then against the digest the server pinned (when it pinned one). The
// checksums bytes that are parsed are the same bytes whose signature passed.
func verifyPinnedArtifact(keyring *Keyring, archivePath, archiveName string, checksums, signature []byte, pinnedDigest string) error {
	if err := verifySignedChecksums(keyring, checksums, signature); err != nil {
		return err
	}
	signed, err := lookupChecksum(checksums, archiveName)
	if err != nil {
		return err
	}
	actual, err := fileSHA256(archivePath)
	if err != nil {
		return Classify(ClassUnknown, fmt.Errorf("failed to hash artifact: %w", err))
	}
	if actual != signed {
		return Classify(ClassDigestMismatch, fmt.Errorf("artifact digest %s does not match the signed checksum %s", actual, signed))
	}
	if pinnedDigest != "" && actual != pinnedDigest {
		return Classify(ClassDigestMismatch, fmt.Errorf("artifact digest %s does not match the pinned digest %s", actual, pinnedDigest))
	}
	return nil
}
