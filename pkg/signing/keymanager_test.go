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

	if err := km.Refresh(); err != nil {
		t.Fatalf("Refresh failed: %v", err)
	}

	key, err := km.GetPublicKey()
	if err != nil {
		t.Fatalf("GetPublicKey failed: %v", err)
	}

	if !pub.Equal(key) {
		t.Error("fetched key does not match expected public key")
	}

	if km.keyID != "key-test-123" {
		t.Errorf("expected key ID 'key-test-123', got '%s'", km.keyID)
	}
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
	if _, err := km.GetPublicKey(); err != nil {
		t.Fatalf("first GetPublicKey failed: %v", err)
	}
	// Second call should use cache
	if _, err := km.GetPublicKey(); err != nil {
		t.Fatalf("second GetPublicKey failed: %v", err)
	}

	if fetchCount.Load() != 1 {
		t.Errorf("expected 1 fetch, got %d", fetchCount.Load())
	}
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

	if _, err := km.GetPublicKey(); err != nil {
		t.Fatalf("first GetPublicKey failed: %v", err)
	}
	// Simulate cache expiry by moving lastFetch into the past
	km.mu.Lock()
	km.lastFetch = time.Now().Add(-2 * time.Hour)
	km.mu.Unlock()

	if _, err := km.GetPublicKey(); err != nil {
		t.Fatalf("second GetPublicKey failed: %v", err)
	}

	if fetchCount.Load() != 2 {
		t.Errorf("expected 2 fetches after cache expiry, got %d", fetchCount.Load())
	}
}

func TestKeyManager_ServerUnavailable(t *testing.T) {
	km := NewKeyManager("http://localhost:1", 3600, "", &http.Client{Timeout: 1 * time.Second})

	_, err := km.GetPublicKey()
	if err == nil {
		t.Error("expected error when server is unavailable")
	}
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
	if err == nil {
		t.Error("expected error for unsupported algorithm")
	}
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
	if err == nil {
		t.Error("expected error for invalid key size")
	}
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
	if err != nil {
		t.Fatalf("first GetPublicKeyForKID failed: %v", err)
	}
	// Second call with same kid should use cache
	key2, err := km.GetPublicKeyForKID("key-test-123")
	if err != nil {
		t.Fatalf("second GetPublicKeyForKID failed: %v", err)
	}

	if !key1.Equal(key2) {
		t.Error("keys should match")
	}
	if fetchCount.Load() != 1 {
		t.Errorf("expected 1 fetch for matching kid, got %d", fetchCount.Load())
	}
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
	if err != nil {
		t.Fatalf("expected success when kid matches active key: %v", err)
	}

	// Request non-matching kid: refresh returns key-v2 again, kid still
	// doesn't match → error. This prevents a compromised relay from
	// directing alpamon to accept an arbitrary key.
	_, err = km.GetPublicKeyForKID("key-v999")
	if err == nil {
		t.Error("expected error when kid doesn't match the active key for this environment")
	}
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
	if err != nil {
		t.Fatalf("first fetch failed: %v", err)
	}
	if !key1.Equal(pub1) {
		t.Error("first key should be pub1")
	}

	// Request key-v2: kid mismatch triggers env-scoped refresh,
	// which now returns key-v2 (rotated active key).
	key2, err := km.GetPublicKeyForKID("key-v2")
	if err != nil {
		t.Fatalf("second fetch failed: %v", err)
	}
	if !key2.Equal(pub2) {
		t.Error("second key should be pub2")
	}
	if fetchCount.Load() != 2 {
		t.Errorf("expected 2 fetches for key rotation, got %d", fetchCount.Load())
	}
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

	if _, err := km.GetPublicKey(); err != nil {
		t.Fatalf("first GetPublicKey failed: %v", err)
	}
	// Should use cache (not expired yet)
	if _, err := km.GetPublicKey(); err != nil {
		t.Fatalf("second GetPublicKey failed: %v", err)
	}
	if fetchCount.Load() != 1 {
		t.Errorf("expected 1 fetch before expiry, got %d", fetchCount.Load())
	}

	// Simulate expires_at having passed by moving it into the past
	km.mu.Lock()
	km.expiresAt = time.Now().Add(-1 * time.Second)
	km.mu.Unlock()

	if _, err := km.GetPublicKey(); err != nil {
		t.Fatalf("third GetPublicKey failed: %v", err)
	}
	if fetchCount.Load() != 2 {
		t.Errorf("expected 2 fetches after expires_at, got %d", fetchCount.Load())
	}
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
	if err != nil {
		t.Fatalf("first fetch should succeed: %v", err)
	}

	// Simulate cache expiry
	km.mu.Lock()
	km.lastFetch = time.Now().Add(-2 * time.Hour)
	km.mu.Unlock()

	// Expired key + refresh failure should return error, not stale key
	_, err = km.GetPublicKey()
	if err == nil {
		t.Error("expected error when key is expired and refresh fails")
	}
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
		got := ResolveAuthEnv(tt.serverURL)
		if got != tt.want {
			t.Errorf("ResolveAuthEnv(%q) = %q, want %q", tt.serverURL, got, tt.want)
		}
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
		got := IsLocalEnv(tt.serverURL)
		if got != tt.want {
			t.Errorf("IsLocalEnv(%q) = %v, want %v", tt.serverURL, got, tt.want)
		}
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
	if err != nil {
		t.Fatalf("GetPublicKey failed: %v", err)
	}
	if !authEnvPresent || receivedAuthEnv != "dev" {
		t.Errorf("expected auth_env=dev in request, got present=%v value=%q", authEnvPresent, receivedAuthEnv)
	}

	// With empty authEnv, requests should not include auth_env param at all
	authEnvPresent = true // reset
	km2 := NewKeyManager(server.URL, 3600, "", server.Client())
	_, err = km2.GetPublicKey()
	if err != nil {
		t.Fatalf("GetPublicKey failed: %v", err)
	}
	if authEnvPresent {
		t.Errorf("expected auth_env param to be absent, but it was present with value %q", receivedAuthEnv)
	}
}
