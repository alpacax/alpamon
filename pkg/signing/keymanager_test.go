package signing

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestServer(pub ed25519.PublicKey) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/commands/public-key/" {
			http.NotFound(w, r)
			return
		}
		resp := publicKeyResponse{
			Algorithm: "Ed25519",
			PublicKey: base64.StdEncoding.EncodeToString(pub),
			KeyID:     "key-test-123",
			ValidFrom: "2026-01-01T00:00:00Z",
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
}

func TestKeyManager_Refresh(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)
	server := newTestServer(pub)
	defer server.Close()

	km := NewKeyManager(server.URL, 3600, "", server.Client())

	require.NoError(t, km.Refresh())

	key, err := km.GetPublicKey()
	require.NoError(t, err)

	assert.Equal(t, pub, key)
	assert.Equal(t, "key-test-123", km.keyID)
}

func TestKeyManager_CacheHit(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)

	var fetchCount atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetchCount.Add(1)
		resp := publicKeyResponse{
			Algorithm: "Ed25519",
			PublicKey: base64.StdEncoding.EncodeToString(pub),
			KeyID:     "key-test",
			ValidFrom: "2026-01-01T00:00:00Z",
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	km := NewKeyManager(server.URL, 3600, "", server.Client())

	// First call fetches
	_, err := km.GetPublicKey()
	require.NoError(t, err)
	// Second call should use cache
	_, err = km.GetPublicKey()
	require.NoError(t, err)

	assert.Equal(t, int32(1), fetchCount.Load())
}

func TestKeyManager_CacheExpiry(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)

	var fetchCount atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetchCount.Add(1)
		resp := publicKeyResponse{
			Algorithm: "Ed25519",
			PublicKey: base64.StdEncoding.EncodeToString(pub),
			KeyID:     "key-test",
			ValidFrom: "2026-01-01T00:00:00Z",
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	km := NewKeyManager(server.URL, 3600, "", server.Client())

	_, err := km.GetPublicKey()
	require.NoError(t, err)
	// Simulate cache expiry by moving lastFetch into the past
	km.mu.Lock()
	km.lastFetch = time.Now().Add(-2 * time.Hour)
	km.mu.Unlock()

	_, err = km.GetPublicKey()
	require.NoError(t, err)

	assert.Equal(t, int32(2), fetchCount.Load())
}

func TestKeyManager_ServerUnavailable(t *testing.T) {
	km := NewKeyManager("http://localhost:1", 3600, "", &http.Client{Timeout: 1 * time.Second})

	_, err := km.GetPublicKey()
	assert.Error(t, err)
}

func TestKeyManager_InvalidAlgorithm(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := publicKeyResponse{
			Algorithm: "RSA",
			PublicKey: base64.StdEncoding.EncodeToString(make([]byte, 32)),
			KeyID:     "key-test",
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	km := NewKeyManager(server.URL, 3600, "", server.Client())

	_, err := km.GetPublicKey()
	assert.Error(t, err)
}

func TestKeyManager_InvalidKeySize(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := publicKeyResponse{
			Algorithm: "Ed25519",
			PublicKey: base64.StdEncoding.EncodeToString([]byte("tooshort")),
			KeyID:     "key-test",
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	km := NewKeyManager(server.URL, 3600, "", server.Client())

	_, err := km.GetPublicKey()
	assert.Error(t, err)
}

func TestKeyManager_GetPublicKeyForKID_CacheHit(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)

	var fetchCount atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetchCount.Add(1)
		resp := publicKeyResponse{
			Algorithm: "Ed25519",
			PublicKey: base64.StdEncoding.EncodeToString(pub),
			KeyID:     "key-test-123",
			ValidFrom: "2026-01-01T00:00:00Z",
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	km := NewKeyManager(server.URL, 3600, "", server.Client())

	// First call fetches
	key1, err := km.GetPublicKeyForKID("key-test-123")
	require.NoError(t, err)
	// Second call with same kid should use cache
	key2, err := km.GetPublicKeyForKID("key-test-123")
	require.NoError(t, err)

	assert.Equal(t, key1, key2)
	assert.Equal(t, int32(1), fetchCount.Load())
}

func TestKeyManager_GetPublicKeyForKID_Mismatch(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)

	// Server always returns the active key for this env (key-v2).
	// Alpamon should reject commands signed with a kid that doesn't match
	// the active key, even after refreshing.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := publicKeyResponse{
			Algorithm: "Ed25519",
			PublicKey: base64.StdEncoding.EncodeToString(pub),
			KeyID:     "key-v2",
			ValidFrom: "2026-01-01T00:00:00Z",
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	km := NewKeyManager(server.URL, 3600, "", server.Client())

	// Request matching kid: success
	_, err := km.GetPublicKeyForKID("key-v2")
	require.NoError(t, err, "expected success when kid matches active key")

	// Request non-matching kid: refresh returns key-v2 again, kid still
	// doesn't match → error. This prevents a compromised relay from
	// directing alpamon to accept an arbitrary key.
	_, err = km.GetPublicKeyForKID("key-v999")
	assert.Error(t, err, "expected error when kid doesn't match the active key for this environment")
}

func TestKeyManager_GetPublicKeyForKID_KeyRotation(t *testing.T) {
	pub1, _, _ := ed25519.GenerateKey(nil)
	pub2, _, _ := ed25519.GenerateKey(nil)

	var fetchCount atomic.Int32
	// Server simulates key rotation: first fetch returns key-v1,
	// subsequent fetches return key-v2 (the new active key).
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := fetchCount.Add(1)
		var pub ed25519.PublicKey
		var kid string
		if n == 1 {
			pub = pub1
			kid = "key-v1"
		} else {
			pub = pub2
			kid = "key-v2"
		}
		resp := publicKeyResponse{
			Algorithm: "Ed25519",
			PublicKey: base64.StdEncoding.EncodeToString(pub),
			KeyID:     kid,
			ValidFrom: "2026-01-01T00:00:00Z",
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	km := NewKeyManager(server.URL, 3600, "", server.Client())

	// Fetch key-v1 (active before rotation)
	key1, err := km.GetPublicKeyForKID("key-v1")
	require.NoError(t, err)
	assert.Equal(t, pub1, key1)

	// Request key-v2: kid mismatch triggers env-scoped refresh,
	// which now returns key-v2 (rotated active key).
	key2, err := km.GetPublicKeyForKID("key-v2")
	require.NoError(t, err)
	assert.Equal(t, pub2, key2)
	assert.Equal(t, int32(2), fetchCount.Load())
}

func TestKeyManager_ExpiresAt(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)

	var fetchCount atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetchCount.Add(1)
		resp := publicKeyResponse{
			Algorithm: "Ed25519",
			PublicKey: base64.StdEncoding.EncodeToString(pub),
			KeyID:     "key-test",
			ValidFrom: "2026-01-01T00:00:00Z",
			ExpiresAt: "2099-01-01T00:00:00Z",
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	km := NewKeyManager(server.URL, 3600, "", server.Client()) // Long TTL, but expires_at overrides

	_, err := km.GetPublicKey()
	require.NoError(t, err)
	// Should use cache (not expired yet)
	_, err = km.GetPublicKey()
	require.NoError(t, err)
	assert.Equal(t, int32(1), fetchCount.Load())

	// Simulate expires_at having passed by moving it into the past
	km.mu.Lock()
	km.expiresAt = time.Now().Add(-1 * time.Second)
	km.mu.Unlock()

	_, err = km.GetPublicKey()
	require.NoError(t, err)
	assert.Equal(t, int32(2), fetchCount.Load())
}

func TestKeyManager_ExpiredKeyRefreshFailure(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)

	var callCount atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if callCount.Add(1) > 1 {
			http.Error(w, "server error", http.StatusInternalServerError)
			return
		}
		resp := publicKeyResponse{
			Algorithm: "Ed25519",
			PublicKey: base64.StdEncoding.EncodeToString(pub),
			KeyID:     "key-test",
			ValidFrom: "2026-01-01T00:00:00Z",
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	km := NewKeyManager(server.URL, 3600, "", server.Client())

	// First fetch succeeds
	_, err := km.GetPublicKey()
	require.NoError(t, err)

	// Simulate cache expiry
	km.mu.Lock()
	km.lastFetch = time.Now().Add(-2 * time.Hour)
	km.mu.Unlock()

	// Expired key + refresh failure should return error, not stale key
	_, err = km.GetPublicKey()
	assert.Error(t, err, "expected error when key is expired and refresh fails")
}

func TestResolveAuthEnv(t *testing.T) {
	tests := []struct {
		serverURL string
		want      string
	}{
		{"https://dev.alpacon.io", "dev"},
		{"https://dev.alpacon.io/", "dev"},
		{"https://us.alpacon.io", ""},
		{"https://kr.alpacon.io", ""},
		{"https://dev.example.com", ""},
		{"http://localhost:8000", ""},
		{"invalid-url", ""},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.want, ResolveAuthEnv(tt.serverURL), "ResolveAuthEnv(%q)", tt.serverURL)
	}
}

func TestIsLocalEnv(t *testing.T) {
	tests := []struct {
		serverURL string
		want      bool
	}{
		{"http://localhost:8000", true},
		{"http://127.0.0.1:8000", true},
		{"http://[::1]:8000", true},
		{"https://dev.alpacon.io", false},
		{"https://us.alpacon.io", false},
		{"invalid-url", false},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.want, IsLocalEnv(tt.serverURL), "IsLocalEnv(%q)", tt.serverURL)
	}
}

func TestKeyManager_AuthEnvQueryParam(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)

	var receivedAuthEnv string
	var authEnvPresent bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, authEnvPresent = r.URL.Query()["auth_env"]
		receivedAuthEnv = r.URL.Query().Get("auth_env")
		resp := publicKeyResponse{
			Algorithm: "Ed25519",
			PublicKey: base64.StdEncoding.EncodeToString(pub),
			KeyID:     "key-dev-1",
			ValidFrom: "2026-01-01T00:00:00Z",
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	// With authEnv="dev", requests should include ?auth_env=dev
	km := NewKeyManager(server.URL, 3600, "dev", server.Client())
	_, err := km.GetPublicKey()
	require.NoError(t, err)
	assert.True(t, authEnvPresent, "expected auth_env in request")
	assert.Equal(t, "dev", receivedAuthEnv)

	// With empty authEnv, requests should not include auth_env param at all
	authEnvPresent = true // reset
	km2 := NewKeyManager(server.URL, 3600, "", server.Client())
	_, err = km2.GetPublicKey()
	require.NoError(t, err)
	assert.False(t, authEnvPresent, "expected auth_env param to be absent, but it was present with value %q", receivedAuthEnv)
}
