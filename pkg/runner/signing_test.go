package runner

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/alpacax/alpamon/internal/protocol"
	"github.com/alpacax/alpamon/pkg/config"
	"github.com/alpacax/alpamon/pkg/signing"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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

	serverID := "server-456"
	origID := config.GlobalSettings.ID
	config.GlobalSettings.ID = serverID
	defer func() { config.GlobalSettings.ID = origID }()

	wc := &WebsocketClient{
		signingMode: "enforce",
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
	signCommand(t, cmd, serverID, priv)

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

	serverID := "server-456"
	origID := config.GlobalSettings.ID
	config.GlobalSettings.ID = serverID
	defer func() { config.GlobalSettings.ID = origID }()

	wc := &WebsocketClient{
		signingMode: "enforce",
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
	signCommand(t, cmd, serverID, differentPriv)

	err = wc.verifyCommandSignature(cmd)
	assert.Error(t, err, "invalid signature should fail")
	assert.Contains(t, err.Error(), "signature verification failed")
}

func TestVerifyCommandSignature_KeyRotation(t *testing.T) {
	// Start with old key, then rotate to new key
	_, oldPriv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	newPub, newPriv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	keyID := "new-key-1"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Always serve the new key (simulating key rotation)
		resp := map[string]string{
			"algorithm":  "Ed25519",
			"public_key": base64.StdEncoding.EncodeToString(newPub),
			"key_id":     keyID,
			"valid_from": "2026-01-01T00:00:00Z",
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	serverID := "server-456"
	origID := config.GlobalSettings.ID
	config.GlobalSettings.ID = serverID
	defer func() { config.GlobalSettings.ID = origID }()

	wc := &WebsocketClient{
		signingMode: "enforce",
		keyManager:  signing.NewKeyManager(server.URL, 3600, nil),
	}

	// First, sign with old key and pre-load old key into cache
	cmdOld := &protocol.Command{
		ID:         "cmd-old",
		Shell:      "system",
		Line:       "whoami",
		User:       "root",
		Group:      "root",
		AnalyzedAt: "2026-03-01T12:00:00+00:00",
		KeyID:      keyID,
	}
	signCommand(t, cmdOld, serverID, oldPriv)

	// This will fail with old key, trigger refresh, fetch new key, but still fail
	// because the command was signed with old key
	err = wc.verifyCommandSignature(cmdOld)
	assert.Error(t, err, "command signed with old key should fail after rotation")

	// Now sign with new key: should succeed (new key already cached from refresh)
	cmdNew := &protocol.Command{
		ID:         "cmd-new",
		Shell:      "system",
		Line:       "whoami",
		User:       "root",
		Group:      "root",
		AnalyzedAt: "2026-03-01T12:00:00+00:00",
		KeyID:      keyID,
	}
	signCommand(t, cmdNew, serverID, newPriv)

	err = wc.verifyCommandSignature(cmdNew)
	assert.NoError(t, err, "command signed with new key should succeed after rotation")
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

	serverID := "server-456"
	origID := config.GlobalSettings.ID
	config.GlobalSettings.ID = serverID
	defer func() { config.GlobalSettings.ID = origID }()

	wc := &WebsocketClient{
		signingMode: "monitor",
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
	signCommand(t, cmd, serverID, differentPriv)

	err = wc.verifyCommandSignature(cmd)
	assert.NoError(t, err, "monitor mode should allow execution even with invalid signature")
}

func TestVerifyCommandSignature_WithoutKeyID(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	server := newTestKeyServer(t, pub, "default-key")
	defer server.Close()

	serverID := "server-456"
	origID := config.GlobalSettings.ID
	config.GlobalSettings.ID = serverID
	defer func() { config.GlobalSettings.ID = origID }()

	wc := &WebsocketClient{
		signingMode: "enforce",
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
	signCommand(t, cmd, serverID, priv)

	err = wc.verifyCommandSignature(cmd)
	assert.NoError(t, err, "should work without key_id using default key")
}

func TestRejectCommandURL(t *testing.T) {
	// Verify the reject URL format is correct
	assert.Equal(t, "/api/events/commands/cmd-123/reject/",
		fmt.Sprintf(eventCommandRejectURL, "cmd-123"))
}
