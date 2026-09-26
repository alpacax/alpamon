package updater

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

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
		{"port without host", PinnedRequest{TargetVersion: "v2.5.0", ChecksumsURL: "https://:443/sums"}, "invalid download URL"},
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
	sm      *fakeServiceManager
	opts    Options
}

func newPinnedFixture(t *testing.T) *pinnedFixture {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the Windows swap moves the running binary aside; covered by the replace tests")
	}
	useTempMarkerDir(t)
	fr := newFakeRelease(t)
	s := newTestSigner(t)
	current := filepath.Join(t.TempDir(), "alpamon")
	require.NoError(t, os.WriteFile(current, fakeBinary(t, "old"), 0755))
	sm := &fakeServiceManager{}
	return &pinnedFixture{
		release: fr,
		signer:  s,
		current: current,
		sm:      sm,
		opts:    Options{BaseURL: fr.srv.URL, Keyring: s.keyring(t), allowHTTP: true, binaryPath: current, ServiceManager: sm},
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

	req := PinnedRequest{
		TargetVersion:  "v2.5.0",
		ArtifactDigest: "sha256:" + sha256Hex(archive),
		AttemptID:      "att-1",
		FromVersion:    "2.4.0",
		HealthGrace:    2 * time.Minute,
	}
	err := PinnedSelfUpdate(context.Background(), req, f.opts)
	require.NoError(t, err)
	t.Cleanup(ReleaseSelfUpdateLatch)

	assert.Equal(t, string(newBin), f.currentContent(t))

	rollback, err := os.ReadFile(f.current + ".rollback")
	require.NoError(t, err, "the outgoing binary is kept until the new one proves healthy")
	assert.Equal(t, string(fakeBinary(t, "old")), string(rollback))

	marker, err := LoadPending()
	require.NoError(t, err)
	require.NotNil(t, marker, "the intent marker is written before the restart")
	assert.Equal(t, "att-1", marker.AttemptID)
	assert.Equal(t, "2.4.0", marker.FromVersion)
	assert.Equal(t, "2.5.0", marker.ToVersion)
	assert.Equal(t, MethodBinary, marker.Method)
	assert.Equal(t, f.current, marker.BinaryPath)
	assert.Equal(t, f.current+".rollback", marker.RollbackPath)
	assert.Equal(t, marker.StartedAt.Add(RestartDelay+2*time.Minute), marker.Deadline)

	restarts, guards, _ := f.sm.snapshot()
	require.Len(t, guards, 1, "the guard is armed before the swap")
	assert.Equal(t, marker.GuardUnit, guards[0].unit)
	assert.Empty(t, restarts, "the caller schedules the restart, not the updater")
}

func TestPinnedSelfUpdate_RefusesWhileAnUpgradeIsPending(t *testing.T) {
	f := newPinnedFixture(t)
	f.release.publish(t, f.signer, "v2.5.0", fakeBinary(t, "new"))
	require.NoError(t, WritePending(&PendingUpgrade{AttemptID: "earlier", ToVersion: "2.4.9", Deadline: time.Now().Add(time.Minute)}))

	err := PinnedSelfUpdate(context.Background(), PinnedRequest{TargetVersion: "v2.5.0"}, f.opts)
	assert.ErrorIs(t, err, ErrUpgradePending)
	assert.Equal(t, string(fakeBinary(t, "old")), f.currentContent(t))
	_, err = os.Stat(f.current + ".rollback")
	assert.ErrorIs(t, err, os.ErrNotExist)
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
			marker, err := LoadPending()
			require.NoError(t, err)
			assert.Nil(t, marker, "nothing is recorded before verification passes")
			_, err = os.Stat(f.current + ".rollback")
			assert.ErrorIs(t, err, os.ErrNotExist)
			_, guards, _ := f.sm.snapshot()
			assert.Empty(t, guards)
		})
	}
}

func TestPinnedSelfUpdate_SharesTheLatchWithSelfUpdate(t *testing.T) {
	require.True(t, selfUpdateInFlight.CompareAndSwap(false, true))
	defer selfUpdateInFlight.Store(false)

	err := PinnedSelfUpdate(context.Background(), PinnedRequest{TargetVersion: "v2.5.0"}, Options{})
	assert.ErrorIs(t, err, ErrSelfUpdateInProgress)
}

func TestPinnedClient_RefusesRedirectToPlainHTTP(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("payload"))
	}))
	t.Cleanup(target.Close)
	// A TLS server that redirects to the plain-HTTP one.
	redirector := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/sums", http.StatusFound)
	}))
	t.Cleanup(redirector.Close)

	client := pinnedClient(5*time.Second, false)
	client.Transport = redirector.Client().Transport

	_, err := downloadBytes(context.Background(), client, redirector.URL+"/sums", 1024)
	assert.ErrorContains(t, err, "must use https")

	// The same redirect is followed when plain HTTP is allowed, which shows
	// the refusal above comes from the scheme check.
	allowed := pinnedClient(5*time.Second, true)
	allowed.Transport = redirector.Client().Transport
	got, err := downloadBytes(context.Background(), allowed, redirector.URL+"/sums", 1024)
	require.NoError(t, err)
	assert.Equal(t, "payload", string(got))
}
