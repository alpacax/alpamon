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
		json.NewEncoder(w).Encode(resp)
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
		json.NewEncoder(w).Encode(resp)
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
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	km := NewKeyManager(server.URL, 1, server.Client()) // 1 second TTL

	if _, err := km.GetPublicKey(); err != nil {
		t.Fatalf("first GetPublicKey failed: %v", err)
	}
	time.Sleep(1100 * time.Millisecond)
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
		json.NewEncoder(w).Encode(resp)
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
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	km := NewKeyManager(server.URL, 3600, server.Client())

	_, err := km.GetPublicKey()
	if err == nil {
		t.Error("expected error for invalid key size")
	}
}

func TestKeyManager_StaleKeyOnRefreshFailure(t *testing.T) {
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
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	km := NewKeyManager(server.URL, 1, server.Client()) // 1 second TTL

	// First fetch succeeds
	key1, err := km.GetPublicKey()
	if err != nil {
		t.Fatalf("first fetch should succeed: %v", err)
	}

	// Wait for cache expiry, next fetch fails but returns stale key
	time.Sleep(1100 * time.Millisecond)
	key2, err := km.GetPublicKey()
	if err != nil {
		t.Fatalf("should return stale key on refresh failure: %v", err)
	}

	if !key1.Equal(key2) {
		t.Error("stale key should match original key")
	}
}
