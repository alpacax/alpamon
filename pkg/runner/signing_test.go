package runner

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/alpacax/alpamon/internal/protocol"
	"github.com/alpacax/alpamon/pkg/signing"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testServerID = "server-456"

// newTestKeyServer creates a test HTTP server that serves a public key.
func newTestKeyServer(t *testing.T, pub ed25519.PublicKey, keyID string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]string{
			"algorithm":  "Ed25519",
			"public_key": base64.StdEncoding.EncodeToString(pub),
			"key_id":     keyID,
			"valid_from": "2026-01-01T00:00:00Z",
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
}

// signCommand signs a command with the given private key and server ID.
func signCommand(t *testing.T, cmd *protocol.Command, serverID string, priv ed25519.PrivateKey) {
	t.Helper()
	payload := signing.BuildCanonicalPayload(cmd, serverID)
	sig := ed25519.Sign(priv, payload)
	cmd.Signature = base64.StdEncoding.EncodeToString(sig)
}

func TestVerifyCommandSignature_InternalBypass(t *testing.T) {
	wc := &WebsocketClient{
		signingMode: "enforce",
		keyManager:  signing.NewKeyManager("http://localhost:9999", 3600, nil),
	}

	cmd := &protocol.Command{
		ID:    "cmd-1",
		Shell: "internal",
		Line:  "ping",
	}

	err := wc.verifyCommandSignature(cmd)
	assert.NoError(t, err, "internal commands should bypass verification")
}

func TestVerifyCommandSignature_NoKeyManager(t *testing.T) {
	wc := &WebsocketClient{
		signingMode: "enforce",
		keyManager:  nil,
	}

	cmd := &protocol.Command{
		ID:    "cmd-1",
		Shell: "system",
		Line:  "whoami",
	}

	err := wc.verifyCommandSignature(cmd)
	assert.NoError(t, err, "should skip when key manager is nil")
}

func TestVerifyCommandSignature_UnsignedMonitorMode(t *testing.T) {
	wc := &WebsocketClient{
		signingMode: "monitor",
		keyManager:  signing.NewKeyManager("http://localhost:9999", 3600, nil),
	}

	cmd := &protocol.Command{
		ID:    "cmd-1",
		Shell: "system",
		Line:  "whoami",
	}

	err := wc.verifyCommandSignature(cmd)
	assert.NoError(t, err, "monitor mode should allow unsigned commands")
}

func TestVerifyCommandSignature_UnsignedEnforceMode(t *testing.T) {
	wc := &WebsocketClient{
		signingMode: "enforce",
		keyManager:  signing.NewKeyManager("http://localhost:9999", 3600, nil),
	}

	cmd := &protocol.Command{
		ID:    "cmd-1",
		Shell: "system",
		Line:  "whoami",
	}

	err := wc.verifyCommandSignature(cmd)
	assert.Error(t, err, "enforce mode should reject unsigned commands")
	assert.Contains(t, err.Error(), "missing signature")
}

func TestVerifyCommandSignature_ValidSignature(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	keyID := "test-key-1"
	server := newTestKeyServer(t, pub, keyID)
	defer server.Close()

	wc := &WebsocketClient{
		signingMode: "enforce",
		serverID:    testServerID,
		keyManager:  signing.NewKeyManager(server.URL, 3600, nil),
	}

	cmd := &protocol.Command{
		ID:         "cmd-123",
		Shell:      "system",
		Line:       "echo hello",
		User:       "root",
		Group:      "root",
		AnalyzedAt: "2026-03-01T12:00:00+00:00",
		KeyID:      keyID,
	}
	signCommand(t, cmd, testServerID, priv)

	err = wc.verifyCommandSignature(cmd)
	assert.NoError(t, err, "valid signature should pass")
}

func TestVerifyCommandSignature_InvalidSignature(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	// Sign with a different key
	_, differentPriv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	keyID := "test-key-1"
	server := newTestKeyServer(t, pub, keyID)
	defer server.Close()

	wc := &WebsocketClient{
		signingMode: "enforce",
		serverID:    testServerID,
		keyManager:  signing.NewKeyManager(server.URL, 3600, nil),
	}

	cmd := &protocol.Command{
		ID:         "cmd-123",
		Shell:      "system",
		Line:       "echo hello",
		User:       "root",
		Group:      "root",
		AnalyzedAt: "2026-03-01T12:00:00+00:00",
		KeyID:      keyID,
	}
	signCommand(t, cmd, testServerID, differentPriv)

	err = wc.verifyCommandSignature(cmd)
	assert.Error(t, err, "invalid signature should fail")
	assert.Contains(t, err.Error(), "signature verification failed")
}

func TestVerifyCommandSignature_KeyRotation(t *testing.T) {
	oldPub, oldPriv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	newPub, newPriv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	keyID := "rotated-key-1"
	var fetchCount atomic.Int32

	// Serve old key on first request, new key on subsequent requests
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := fetchCount.Add(1)
		var pub ed25519.PublicKey
		if n == 1 {
			pub = oldPub
		} else {
			pub = newPub
		}
		resp := map[string]string{
			"algorithm":  "Ed25519",
			"public_key": base64.StdEncoding.EncodeToString(pub),
			"key_id":     keyID,
			"valid_from": "2026-01-01T00:00:00Z",
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	wc := &WebsocketClient{
		signingMode: "enforce",
		serverID:    testServerID,
		keyManager:  signing.NewKeyManager(server.URL, 3600, nil),
	}

	// Pre-populate cache with old key by verifying a command signed with it
	cmdOld := &protocol.Command{
		ID:         "cmd-old",
		Shell:      "system",
		Line:       "whoami",
		User:       "root",
		Group:      "root",
		AnalyzedAt: "2026-03-01T12:00:00+00:00",
		KeyID:      keyID,
	}
	signCommand(t, cmdOld, testServerID, oldPriv)
	err = wc.verifyCommandSignature(cmdOld)
	require.NoError(t, err, "command signed with old key should pass initially")
	require.Equal(t, int32(1), fetchCount.Load(), "should have fetched key once")

	// Now sign a command with the new key. First verification attempt uses
	// the cached old key and fails, triggering ForceRefresh which fetches the
	// new key, and the retry succeeds.
	cmdNew := &protocol.Command{
		ID:         "cmd-new",
		Shell:      "system",
		Line:       "whoami",
		User:       "root",
		Group:      "root",
		AnalyzedAt: "2026-03-01T12:00:00+00:00",
		KeyID:      keyID,
	}
	signCommand(t, cmdNew, testServerID, newPriv)

	err = wc.verifyCommandSignature(cmdNew)
	assert.NoError(t, err, "command signed with new key should succeed after key rotation")
	assert.Equal(t, int32(2), fetchCount.Load(),
		"should have fetched key twice: initial + ForceRefresh for rotation")
}

func TestVerifyCommandSignature_KeyUnavailableMonitorMode(t *testing.T) {
	// AI server returns 500
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	wc := &WebsocketClient{
		signingMode: "monitor",
		keyManager:  signing.NewKeyManager(server.URL, 3600, nil),
	}

	cmd := &protocol.Command{
		ID:        "cmd-1",
		Shell:     "system",
		Line:      "whoami",
		Signature: "some-signature",
	}

	err := wc.verifyCommandSignature(cmd)
	assert.NoError(t, err, "monitor mode should allow when key unavailable")
}

func TestVerifyCommandSignature_KeyUnavailableEnforceMode(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	wc := &WebsocketClient{
		signingMode: "enforce",
		keyManager:  signing.NewKeyManager(server.URL, 3600, nil),
	}

	cmd := &protocol.Command{
		ID:        "cmd-1",
		Shell:     "system",
		Line:      "whoami",
		Signature: "some-signature",
	}

	err := wc.verifyCommandSignature(cmd)
	assert.Error(t, err, "enforce mode should reject when key unavailable")
	assert.Contains(t, err.Error(), "public key unavailable")
}

func TestVerifyCommandSignature_InvalidSignatureMonitorMode(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	// Sign with a different key
	_, differentPriv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	keyID := "test-key-1"
	server := newTestKeyServer(t, pub, keyID)
	defer server.Close()

	wc := &WebsocketClient{
		signingMode: "monitor",
		serverID:    testServerID,
		keyManager:  signing.NewKeyManager(server.URL, 3600, nil),
	}

	cmd := &protocol.Command{
		ID:         "cmd-123",
		Shell:      "system",
		Line:       "echo hello",
		User:       "root",
		Group:      "root",
		AnalyzedAt: "2026-03-01T12:00:00+00:00",
		KeyID:      keyID,
	}
	signCommand(t, cmd, testServerID, differentPriv)

	err = wc.verifyCommandSignature(cmd)
	assert.NoError(t, err, "monitor mode should allow execution even with invalid signature")
}

func TestVerifyCommandSignature_WithoutKeyID(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	server := newTestKeyServer(t, pub, "default-key")
	defer server.Close()

	wc := &WebsocketClient{
		signingMode: "enforce",
		serverID:    testServerID,
		keyManager:  signing.NewKeyManager(server.URL, 3600, nil),
	}

	cmd := &protocol.Command{
		ID:         "cmd-123",
		Shell:      "system",
		Line:       "echo hello",
		User:       "root",
		Group:      "root",
		AnalyzedAt: "2026-03-01T12:00:00+00:00",
		// No KeyID: uses GetPublicKey() instead of GetPublicKeyForKID()
	}
	signCommand(t, cmd, testServerID, priv)

	err = wc.verifyCommandSignature(cmd)
	assert.NoError(t, err, "should work without key_id using default key")
}

func TestRejectCommandURL(t *testing.T) {
	// Verify the reject URL format is correct
	assert.Equal(t, "/api/events/commands/cmd-123/reject/",
		fmt.Sprintf(eventCommandRejectURL, "cmd-123"))
}
