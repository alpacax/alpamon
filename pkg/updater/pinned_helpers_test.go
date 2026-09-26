package updater

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/stretchr/testify/require"
)

// testSigner is a signing key generated per test. It is test-only: nothing
// signed with it can pass a production build, whose keyring is compiled in.
type testSigner struct {
	entity *openpgp.Entity
}

func newTestSigner(t *testing.T) *testSigner {
	t.Helper()
	e, err := openpgp.NewEntity("alpamon test signing key", "test only", "test@example.invalid",
		&packet.Config{Algorithm: packet.PubKeyAlgoEdDSA})
	require.NoError(t, err)
	return &testSigner{entity: e}
}

// armoredPublic returns the public key as an ASCII-armored block.
func (s *testSigner) armoredPublic(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	w, err := armor.Encode(&buf, openpgp.PublicKeyType, nil)
	require.NoError(t, err)
	require.NoError(t, s.entity.Serialize(w))
	require.NoError(t, w.Close())
	return buf.Bytes()
}

func (s *testSigner) keyring(t *testing.T) *Keyring {
	t.Helper()
	kr, err := ParseKeyring(s.armoredPublic(t))
	require.NoError(t, err)
	require.Equal(t, 1, kr.Len())
	return kr
}

func (s *testSigner) sign(t *testing.T, data []byte, armored bool) []byte {
	t.Helper()
	var buf bytes.Buffer
	if armored {
		require.NoError(t, openpgp.ArmoredDetachSign(&buf, s.entity, bytes.NewReader(data), nil))
	} else {
		require.NoError(t, openpgp.DetachSign(&buf, s.entity, bytes.NewReader(data), nil))
	}
	return buf.Bytes()
}

// fakeBinary returns bytes that pass validateBinaryFormat on this platform.
func fakeBinary(t *testing.T, payload string) []byte {
	t.Helper()
	switch runtime.GOOS {
	case "linux":
		return append([]byte{0x7f, 'E', 'L', 'F'}, payload...)
	case "darwin":
		return append([]byte{0xCF, 0xFA, 0xED, 0xFE}, payload...)
	default:
		t.Skipf("no fake binary format for %s", runtime.GOOS)
		return nil
	}
}

// fakeRelease is an artifact server laid out like a GitHub release. It
// counts requests so a test can prove nothing was fetched.
type fakeRelease struct {
	srv   *httptest.Server
	mu    sync.Mutex
	files map[string][]byte
	hits  int
}

func newFakeRelease(t *testing.T) *fakeRelease {
	t.Helper()
	fr := &fakeRelease{files: map[string][]byte{}}
	fr.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fr.mu.Lock()
		fr.hits++
		body, ok := fr.files[r.URL.Path]
		fr.mu.Unlock()
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(body)
	}))
	t.Cleanup(fr.srv.Close)
	return fr
}

func (fr *fakeRelease) put(path string, body []byte) {
	fr.mu.Lock()
	defer fr.mu.Unlock()
	fr.files[path] = body
}

func (fr *fakeRelease) requests() int {
	fr.mu.Lock()
	defer fr.mu.Unlock()
	return fr.hits
}

// publish lays out a signed release for tag: the archive, the checksums file
// and its detached signature at the default URLs. It returns the archive.
func (fr *fakeRelease) publish(t *testing.T, s *testSigner, tag string, binary []byte) []byte {
	t.Helper()
	archive := createTestArchive(t, binary)
	name := archiveFilename(tag)
	v := strings.TrimPrefix(tag, "v")
	checksums := fmt.Sprintf("%s  %s\n%s  alpamon-%s-other-arch.tar.gz\n", sha256Hex(archive), name, strings.Repeat("0", 64), v)
	fr.put("/"+tag+"/"+name, archive)
	fr.put(fmt.Sprintf("/%s/alpamon-%s-checksums.sha256", tag, v), []byte(checksums))
	fr.put(fmt.Sprintf("/%s/alpamon-%s-checksums.sha256%s", tag, v, signatureSuffix), s.sign(t, []byte(checksums), true))
	return archive
}
