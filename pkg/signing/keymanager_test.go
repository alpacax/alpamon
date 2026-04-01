package signing

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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

	km := NewKeyManager(server.URL, 3600, server.Client())

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

	fetchCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetchCount++
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

	km := NewKeyManager(server.URL, 3600, server.Client())

	// First call fetches
	if _, err := km.GetPublicKey(); err != nil {
		t.Fatalf("first GetPublicKey failed: %v", err)
	}
	// Second call should use cache
	if _, err := km.GetPublicKey(); err != nil {
		t.Fatalf("second GetPublicKey failed: %v", err)
	}

	if fetchCount != 1 {
		t.Errorf("expected 1 fetch, got %d", fetchCount)
	}
}

func TestKeyManager_CacheExpiry(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)

	fetchCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetchCount++
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

	km := NewKeyManager(server.URL, 3600, server.Client())

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

	if fetchCount != 2 {
		t.Errorf("expected 2 fetches after cache expiry, got %d", fetchCount)
	}
}

func TestKeyManager_ServerUnavailable(t *testing.T) {
	km := NewKeyManager("http://localhost:1", 3600, &http.Client{Timeout: 1 * time.Second})

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

	km := NewKeyManager(server.URL, 3600, server.Client())

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

	km := NewKeyManager(server.URL, 3600, server.Client())

	_, err := km.GetPublicKey()
	if err == nil {
		t.Error("expected error for invalid key size")
	}
}

func TestKeyManager_GetPublicKeyForKID_CacheHit(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)

	fetchCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetchCount++
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

	km := NewKeyManager(server.URL, 3600, server.Client())

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
	if fetchCount != 1 {
		t.Errorf("expected 1 fetch for matching kid, got %d", fetchCount)
	}
}

func TestKeyManager_GetPublicKeyForKID_Mismatch(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)

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

	km := NewKeyManager(server.URL, 3600, server.Client())

	// Request unknown kid, server returns key-v2
	_, err := km.GetPublicKeyForKID("key-v2")
	if err != nil {
		t.Fatalf("expected success when server returns matching kid: %v", err)
	}

	// Request a kid that doesn't match what server returns
	_, err = km.GetPublicKeyForKID("key-v999")
	if err == nil {
		t.Error("expected error when kid doesn't match after refresh")
	}
}

func TestKeyManager_GetPublicKeyForKID_KeyRotation(t *testing.T) {
	pub1, _, _ := ed25519.GenerateKey(nil)
	pub2, _, _ := ed25519.GenerateKey(nil)

	fetchCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetchCount++
		var pub ed25519.PublicKey
		var kid string
		if fetchCount == 1 {
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

	km := NewKeyManager(server.URL, 3600, server.Client())

	// Fetch key-v1
	key1, err := km.GetPublicKeyForKID("key-v1")
	if err != nil {
		t.Fatalf("first fetch failed: %v", err)
	}
	if !key1.Equal(pub1) {
		t.Error("first key should be pub1")
	}

	// Request key-v2 triggers refresh
	key2, err := km.GetPublicKeyForKID("key-v2")
	if err != nil {
		t.Fatalf("second fetch failed: %v", err)
	}
	if !key2.Equal(pub2) {
		t.Error("second key should be pub2")
	}
	if fetchCount != 2 {
		t.Errorf("expected 2 fetches for key rotation, got %d", fetchCount)
	}
}

func TestKeyManager_ExpiresAt(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)

	fetchCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetchCount++
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

	km := NewKeyManager(server.URL, 3600, server.Client()) // Long TTL, but expires_at overrides

	if _, err := km.GetPublicKey(); err != nil {
		t.Fatalf("first GetPublicKey failed: %v", err)
	}
	// Should use cache (not expired yet)
	if _, err := km.GetPublicKey(); err != nil {
		t.Fatalf("second GetPublicKey failed: %v", err)
	}
	if fetchCount != 1 {
		t.Errorf("expected 1 fetch before expiry, got %d", fetchCount)
	}

	// Simulate expires_at having passed by moving it into the past
	km.mu.Lock()
	km.expiresAt = time.Now().Add(-1 * time.Second)
	km.mu.Unlock()

	if _, err := km.GetPublicKey(); err != nil {
		t.Fatalf("third GetPublicKey failed: %v", err)
	}
	if fetchCount != 2 {
		t.Errorf("expected 2 fetches after expires_at, got %d", fetchCount)
	}
}

func TestKeyManager_ExpiredKeyRefreshFailure(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)

	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		if callCount > 1 {
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

	km := NewKeyManager(server.URL, 3600, server.Client())

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
