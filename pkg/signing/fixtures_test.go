package signing

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/alpacax/alpamon/v2/internal/protocol"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	return pub, priv
}

// testKeyResponse is what the AI server returns for an active Ed25519 key.
func testKeyResponse(pub ed25519.PublicKey, kid string) publicKeyResponse {
	return publicKeyResponse{
		Algorithm: "Ed25519",
		PublicKey: base64.StdEncoding.EncodeToString(pub),
		KeyID:     kid,
		ValidFrom: "2026-01-01T00:00:00Z",
	}
}

func writeKeyResponse(t *testing.T, w http.ResponseWriter, resp publicKeyResponse) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	assert.NoError(t, json.NewEncoder(w).Encode(resp))
}

// keyServer serves resp for every request, counting fetches when count is non-nil.
func keyServer(t *testing.T, count *atomic.Int32, resp publicKeyResponse) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if count != nil {
			count.Add(1)
		}
		writeKeyResponse(t, w, resp)
	}))
}

func newTestServer(t *testing.T, pub ed25519.PublicKey, kid string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/commands/public-key/" {
			http.NotFound(w, r)
			return
		}
		writeKeyResponse(t, w, testKeyResponse(pub, kid))
	}))
}

const testServerID = "server-456"

func testCommand(sig string) *protocol.Command {
	return &protocol.Command{
		ID:         "cmd-123",
		Shell:      "system",
		Line:       "whoami",
		User:       "root",
		Group:      "root",
		AnalyzedAt: "2026-03-01T12:00:00+00:00",
		Signature:  sig,
	}
}

// signedCommand returns a command carrying a signature valid for serverID.
func signedCommand(t *testing.T, priv ed25519.PrivateKey, serverID string) *protocol.Command {
	t.Helper()
	cmd := testCommand("")
	cmd.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, BuildCanonicalPayload(cmd, serverID)))
	return cmd
}
