package updater

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNormalizeTag(t *testing.T) {
	for in, want := range map[string]string{"v2.5.0": "v2.5.0", "2.5.0": "v2.5.0", " 2.5.0-rc.1 ": "v2.5.0-rc.1"} {
		got, err := NormalizeTag(in)
		require.NoError(t, err)
		assert.Equal(t, want, got)
	}
	for _, in := range []string{"", "latest", "v1.0.0; rm -rf /", "../v1.0.0"} {
		_, err := NormalizeTag(in)
		assert.Error(t, err, in)
	}
}

func TestResolvePinned(t *testing.T) {
	name := archiveFilename("v2.5.0")

	t.Run("defaults follow the release layout", func(t *testing.T) {
		src, err := resolvePinned(PinnedRequest{TargetVersion: "2.5.0"}, Options{})
		require.NoError(t, err)
		assert.Equal(t, defaultReleaseBaseURL+"/v2.5.0/"+name, src.artifactURL)
		assert.Equal(t, defaultReleaseBaseURL+"/v2.5.0/alpamon-2.5.0-checksums.sha256", src.checksumsURL)
		assert.Equal(t, src.checksumsURL+".sig", src.signatureURL)
	})

	t.Run("server URLs are used as given", func(t *testing.T) {
		req := PinnedRequest{
			TargetVersion: "v2.5.0",
			ArtifactURL:   "https://mirror.example/r/" + name,
			ChecksumsURL:  "https://mirror.example/r/sums",
			SignatureURL:  "https://mirror.example/r/sums.asc",
		}
		src, err := resolvePinned(req, Options{})
		require.NoError(t, err)
		assert.Equal(t, req.ArtifactURL, src.artifactURL)
		assert.Equal(t, req.ChecksumsURL, src.checksumsURL)
		assert.Equal(t, req.SignatureURL, src.signatureURL)
	})

	bad := []struct {
		name string
		req  PinnedRequest
		want string
	}{
		{"plain http", PinnedRequest{TargetVersion: "v2.5.0", ChecksumsURL: "http://mirror.example/sums"}, "must use https"},
		{"other platform's archive", PinnedRequest{TargetVersion: "v2.5.0", ArtifactURL: "https://mirror.example/alpamon-2.5.0-plan9-mips.tar.gz"}, "archive for this platform"},
		{"other version's archive", PinnedRequest{TargetVersion: "v2.5.0", ArtifactURL: "https://mirror.example/" + archiveFilename("v2.4.0")}, "archive for this platform"},
		{"bad version", PinnedRequest{TargetVersion: "latest"}, "invalid version"},
		{"bad digest", PinnedRequest{TargetVersion: "v2.5.0", ArtifactDigest: "abc"}, "not a SHA-256"},
		{"no host", PinnedRequest{TargetVersion: "v2.5.0", SignatureURL: "https:///sums.sig"}, "invalid download URL"},
	}
	for _, tt := range bad {
		t.Run(tt.name, func(t *testing.T) {
			_, err := resolvePinned(tt.req, Options{})
			assert.ErrorContains(t, err, tt.want)
		})
	}
}

// pinnedFixture is a fake release plus a stand-in for the running binary.
type pinnedFixture struct {
	release *fakeRelease
	signer  *testSigner
	current string
	opts    Options
}

func newPinnedFixture(t *testing.T) *pinnedFixture {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the Windows swap moves the running binary aside; covered by the replace tests")
	}
	fr := newFakeRelease(t)
	s := newTestSigner(t)
	current := filepath.Join(t.TempDir(), "alpamon")
	require.NoError(t, os.WriteFile(current, fakeBinary(t, "old"), 0755))
	return &pinnedFixture{
		release: fr,
		signer:  s,
		current: current,
		opts:    Options{BaseURL: fr.srv.URL, Keyring: s.keyring(t), allowHTTP: true, binaryPath: current},
	}
}

func (f *pinnedFixture) currentContent(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(f.current)
	require.NoError(t, err)
	return string(b)
}

func TestPinnedSelfUpdate_ReplacesBinaryAfterVerification(t *testing.T) {
	f := newPinnedFixture(t)
	newBin := fakeBinary(t, "new")
	archive := f.release.publish(t, f.signer, "v2.5.0", newBin)

	err := PinnedSelfUpdate(context.Background(), PinnedRequest{TargetVersion: "v2.5.0", ArtifactDigest: "sha256:" + sha256Hex(archive)}, f.opts)
	require.NoError(t, err)
	t.Cleanup(ReleaseSelfUpdateLatch)

	assert.Equal(t, string(newBin), f.currentContent(t))
}

func TestPinnedSelfUpdate_RefusesWithoutKeysBeforeDownloading(t *testing.T) {
	f := newPinnedFixture(t)
	f.release.publish(t, f.signer, "v2.5.0", fakeBinary(t, "new"))
	f.opts.Keyring = nil // falls back to the compiled bundle, empty in this build

	err := PinnedSelfUpdate(context.Background(), PinnedRequest{TargetVersion: "v2.5.0"}, f.opts)
	assert.ErrorIs(t, err, ErrNoTrustedKeys)
	assert.Equal(t, ClassSignatureInvalid, ClassOf(err))
	assert.Zero(t, f.release.requests(), "nothing may be fetched without a key to verify it")
	assert.Equal(t, string(fakeBinary(t, "old")), f.currentContent(t))
	assert.False(t, selfUpdateInFlight.Load(), "a failed run releases the latch")
}

func TestPinnedSelfUpdate_FailuresLeaveBinaryUntouched(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(t *testing.T, f *pinnedFixture, archive []byte) PinnedRequest
		class  ErrorClass
	}{
		{
			name: "artifact missing",
			mutate: func(t *testing.T, f *pinnedFixture, _ []byte) PinnedRequest {
				delete(f.release.files, "/v2.5.0/"+archiveFilename("v2.5.0"))
				return PinnedRequest{TargetVersion: "v2.5.0"}
			},
			class: ClassDownloadFailed,
		},
		{
			name: "signature missing",
			mutate: func(t *testing.T, f *pinnedFixture, _ []byte) PinnedRequest {
				delete(f.release.files, "/v2.5.0/alpamon-2.5.0-checksums.sha256.sig")
				return PinnedRequest{TargetVersion: "v2.5.0"}
			},
			class: ClassDownloadFailed,
		},
		{
			name: "signed by another key",
			mutate: func(t *testing.T, f *pinnedFixture, _ []byte) PinnedRequest {
				sums := f.release.files["/v2.5.0/alpamon-2.5.0-checksums.sha256"]
				f.release.put("/v2.5.0/alpamon-2.5.0-checksums.sha256.sig", newTestSigner(t).sign(t, sums, true))
				return PinnedRequest{TargetVersion: "v2.5.0"}
			},
			class: ClassSignatureInvalid,
		},
		{
			name: "artifact swapped after signing",
			mutate: func(t *testing.T, f *pinnedFixture, _ []byte) PinnedRequest {
				f.release.put("/v2.5.0/"+archiveFilename("v2.5.0"), createTestArchive(t, fakeBinary(t, "evil")))
				return PinnedRequest{TargetVersion: "v2.5.0"}
			},
			class: ClassDigestMismatch,
		},
		{
			name: "pinned digest disagrees",
			mutate: func(t *testing.T, f *pinnedFixture, _ []byte) PinnedRequest {
				return PinnedRequest{TargetVersion: "v2.5.0", ArtifactDigest: strings.Repeat("e", 64)}
			},
			class: ClassDigestMismatch,
		},
		{
			name: "archive holds no valid binary",
			mutate: func(t *testing.T, f *pinnedFixture, _ []byte) PinnedRequest {
				f2 := newFakeRelease(t)
				f.release.files = f2.files
				f.release.publish(t, f.signer, "v2.5.0", []byte("#!/bin/sh\n"))
				return PinnedRequest{TargetVersion: "v2.5.0"}
			},
			class: ClassUnknown,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newPinnedFixture(t)
			archive := f.release.publish(t, f.signer, "v2.5.0", fakeBinary(t, "new"))
			req := tt.mutate(t, f, archive)

			err := PinnedSelfUpdate(context.Background(), req, f.opts)
			require.Error(t, err)
			assert.Equal(t, tt.class, ClassOf(err), err.Error())
			assert.Equal(t, string(fakeBinary(t, "old")), f.currentContent(t))
			assert.False(t, selfUpdateInFlight.Load())
		})
	}
}

func TestPinnedSelfUpdate_SharesTheLatchWithSelfUpdate(t *testing.T) {
	require.True(t, selfUpdateInFlight.CompareAndSwap(false, true))
	defer selfUpdateInFlight.Store(false)

	err := PinnedSelfUpdate(context.Background(), PinnedRequest{TargetVersion: "v2.5.0"}, Options{})
	assert.ErrorIs(t, err, ErrSelfUpdateInProgress)
}
