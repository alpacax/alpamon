package updater

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReleaseKeyring_DefaultBuildIsEmpty(t *testing.T) {
	kr, err := ReleaseKeyring()
	require.NoError(t, err)
	assert.Zero(t, kr.Len(), "a build without the release key tag must carry no signing key")
}

func TestParseKeyring(t *testing.T) {
	a, b := newTestSigner(t), newTestSigner(t)

	kr, err := ParseKeyring(append(append(a.armoredPublic(t), '\n'), b.armoredPublic(t)...))
	require.NoError(t, err)
	assert.Equal(t, 2, kr.Len(), "every concatenated block is read")

	empty, err := ParseKeyring(nil)
	require.NoError(t, err)
	assert.Zero(t, empty.Len())

	_, err = ParseKeyring([]byte("not a key"))
	assert.Error(t, err)

	sig := a.sign(t, []byte("x"), true)
	_, err = ParseKeyring(sig)
	assert.ErrorContains(t, err, "unexpected armor block")
}

func TestVerifySignedChecksums(t *testing.T) {
	s := newTestSigner(t)
	kr := s.keyring(t)
	checksums := []byte("abc  alpamon.tar.gz\n")

	require.NoError(t, verifySignedChecksums(kr, checksums, s.sign(t, checksums, true)), "armored")
	require.NoError(t, verifySignedChecksums(kr, checksums, s.sign(t, checksums, false)), "binary")

	tests := []struct {
		name    string
		keyring *Keyring
		data    []byte
		sig     []byte
	}{
		{"nil keyring", nil, checksums, s.sign(t, checksums, true)},
		{"empty keyring", &Keyring{}, checksums, s.sign(t, checksums, true)},
		{"other key", newTestSigner(t).keyring(t), checksums, s.sign(t, checksums, true)},
		{"tampered checksums", kr, []byte("abd  alpamon.tar.gz\n"), s.sign(t, checksums, true)},
		{"garbage signature", kr, checksums, []byte("garbage")},
		{"empty signature", kr, checksums, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := verifySignedChecksums(tt.keyring, tt.data, tt.sig)
			assert.Equal(t, ClassSignatureInvalid, ClassOf(err))
		})
	}

	assert.ErrorIs(t, verifySignedChecksums(&Keyring{}, checksums, nil), ErrNoTrustedKeys)
}

func TestLookupChecksum(t *testing.T) {
	good := strings.Repeat("a", 64)
	tests := []struct {
		name      string
		checksums string
		want      string
		wantErr   string
	}{
		{"found", good + "  a.tar.gz\n" + strings.Repeat("b", 64) + "  b.tar.gz\n", good, ""},
		{"binary mode marker", good + " *a.tar.gz\n", good, ""},
		{"uppercase normalized", strings.ToUpper(good) + "  a.tar.gz\n", good, ""},
		{"missing", good + "  b.tar.gz\n", "", "no entry"},
		{"duplicate", good + "  a.tar.gz\n" + good + "  a.tar.gz\n", "", "more than once"},
		{"not a digest", "xyz  a.tar.gz\n", "", "not a SHA-256"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := lookupChecksum([]byte(tt.checksums), "a.tar.gz")
			if tt.wantErr != "" {
				assert.ErrorContains(t, err, tt.wantErr)
				assert.Equal(t, ClassDigestMismatch, ClassOf(err))
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestNormalizeDigest(t *testing.T) {
	d := strings.Repeat("c", 64)
	for _, in := range []string{d, "sha256:" + d, "SHA256:" + strings.ToUpper(d)} {
		got, err := normalizeDigest(in)
		require.NoError(t, err)
		assert.Equal(t, d, got)
	}
	got, err := normalizeDigest("")
	require.NoError(t, err)
	assert.Empty(t, got)

	_, err = normalizeDigest("md5:abc")
	assert.Error(t, err)
}

func TestVerifyPinnedArtifact(t *testing.T) {
	s := newTestSigner(t)
	kr := s.keyring(t)
	archive := []byte("archive bytes")
	archivePath := filepath.Join(t.TempDir(), "a.tar.gz")
	require.NoError(t, os.WriteFile(archivePath, archive, 0600))
	digest := sha256Hex(archive)
	checksums := []byte(digest + "  a.tar.gz\n")
	sig := s.sign(t, checksums, true)

	t.Run("passes with and without a pinned digest", func(t *testing.T) {
		require.NoError(t, verifyPinnedArtifact(kr, archivePath, "a.tar.gz", checksums, sig, digest))
		require.NoError(t, verifyPinnedArtifact(kr, archivePath, "a.tar.gz", checksums, sig, ""))
	})

	t.Run("signature is checked before any digest", func(t *testing.T) {
		wrong := []byte(strings.Repeat("0", 64) + "  a.tar.gz\n")
		err := verifyPinnedArtifact(kr, archivePath, "a.tar.gz", wrong, sig, strings.Repeat("1", 64))
		assert.Equal(t, ClassSignatureInvalid, ClassOf(err))
	})

	t.Run("artifact does not match the signed line", func(t *testing.T) {
		other := []byte(strings.Repeat("0", 64) + "  a.tar.gz\n")
		err := verifyPinnedArtifact(kr, archivePath, "a.tar.gz", other, s.sign(t, other, true), "")
		assert.Equal(t, ClassDigestMismatch, ClassOf(err))
		assert.ErrorContains(t, err, "signed checksum")
	})

	t.Run("artifact does not match the pinned digest", func(t *testing.T) {
		err := verifyPinnedArtifact(kr, archivePath, "a.tar.gz", checksums, sig, strings.Repeat("1", 64))
		assert.Equal(t, ClassDigestMismatch, ClassOf(err))
		assert.ErrorContains(t, err, "pinned digest")
	})

	t.Run("signed file does not list the artifact", func(t *testing.T) {
		err := verifyPinnedArtifact(kr, archivePath, "b.tar.gz", checksums, sig, "")
		assert.Equal(t, ClassDigestMismatch, ClassOf(err))
	})

	t.Run("empty keyring refuses", func(t *testing.T) {
		err := verifyPinnedArtifact(&Keyring{}, archivePath, "a.tar.gz", checksums, sig, digest)
		assert.ErrorIs(t, err, ErrNoTrustedKeys)
	})

	// Guard against a keyring type that silently accepts: the signature must
	// commit to the exact bytes.
	t.Run("trailing byte breaks the signature", func(t *testing.T) {
		err := verifyPinnedArtifact(kr, archivePath, "a.tar.gz", bytes.Clone(append(checksums, ' ')), sig, "")
		assert.Equal(t, ClassSignatureInvalid, ClassOf(err))
	})
}

func TestClassify(t *testing.T) {
	assert.NoError(t, Classify(ClassUnknown, nil))
	assert.Equal(t, ErrorClass(""), ClassOf(nil))
	assert.Equal(t, ClassUnknown, ClassOf(assert.AnError))

	err := Classify(ClassDownloadFailed, assert.AnError)
	assert.Equal(t, ClassDownloadFailed, ClassOf(err))
	assert.ErrorIs(t, err, assert.AnError)
	assert.Equal(t, ClassDownloadFailed, ClassOf(Classify(ClassUnknown, err)), "first class wins")
}
