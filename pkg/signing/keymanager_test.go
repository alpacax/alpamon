package signing

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResolveAuthEnv(t *testing.T) {
	tests := []struct {
		serverURL string
		want      string
	}{
		{"https://dev.alpacon.io", "dev"},
		{"https://dev.alpacon.io/", "dev"},
		// A workspace URL, which is what alpamon.conf actually carries.
		{"https://alpacax.dev.alpacon.io", "dev"},
		{"https://Alpacax.DEV.alpacon.io/", "dev"},
		{"https://alpacax.dev.alpacon.io.", "dev"},
		{"https://dev.alpacon.io.", "dev"},
		{"https://alpacax.alpacon.io", ""},
		{"https://us.alpacon.io", ""},
		{"https://kr.alpacon.io", ""},
		// Only a real subdomain counts, not a name that happens to contain it.
		{"https://notdev.alpacon.io", ""},
		{"https://dev.alpacon.io.example.com", ""},
		{"https://dev.example.com", ""},
		{"http://localhost:8000", ""},
		{"invalid-url", ""},
	}
	for _, tt := range tests {
		t.Run(tt.serverURL, func(t *testing.T) {
			assert.Equal(t, tt.want, ResolveAuthEnv(tt.serverURL))
		})
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
		t.Run(tt.serverURL, func(t *testing.T) {
			assert.Equal(t, tt.want, IsLocalEnv(tt.serverURL))
		})
	}
}

func TestKeyManager_Refresh(t *testing.T) {
	pub, _ := testKey(t)
	server := pathCheckingKeyServer(t, pub, "key-test-123")

	km := NewKeyManager(server.URL, 3600, "", server.Client())

	require.NoError(t, km.Refresh())

	key, err := km.GetPublicKey()
	require.NoError(t, err)

	assert.Equal(t, pub, key)
	assert.Equal(t, "key-test-123", km.keyID)
}

func TestKeyManager_CacheHit(t *testing.T) {
	pub, _ := testKey(t)

	server, fetchCount := keyServer(t, testKeyResponse(pub, "key-test"))

	km := NewKeyManager(server.URL, 3600, "", server.Client())

	_, err := km.GetPublicKey()
	require.NoError(t, err)
	_, err = km.GetPublicKey()
	require.NoError(t, err)

	assert.Equal(t, int32(1), fetchCount.Load())
}

func TestKeyManager_CacheExpiry(t *testing.T) {
	pub, _ := testKey(t)

	server, fetchCount := keyServer(t, testKeyResponse(pub, "key-test"))

	km := NewKeyManager(server.URL, 3600, "", server.Client())

	_, err := km.GetPublicKey()
	require.NoError(t, err)
	// Simulate cache expiry
	km.mu.Lock()
	km.lastFetch = time.Now().Add(-2 * time.Hour)
	km.mu.Unlock()

	_, err = km.GetPublicKey()
	require.NoError(t, err)

	assert.Equal(t, int32(2), fetchCount.Load())
}

func TestKeyManager_ExpiresAt(t *testing.T) {
	pub, _ := testKey(t)

	resp := testKeyResponse(pub, "key-test")
	resp.ExpiresAt = "2099-01-01T00:00:00Z"
	server, fetchCount := keyServer(t, resp)

	km := NewKeyManager(server.URL, 3600, "", server.Client()) // Long TTL, but expires_at overrides

	_, err := km.GetPublicKey()
	require.NoError(t, err)
	_, err = km.GetPublicKey()
	require.NoError(t, err)
	assert.Equal(t, int32(1), fetchCount.Load())

	// Simulate expires_at having passed
	km.mu.Lock()
	km.expiresAt = new(time.Now().Add(-time.Second))
	km.lastFetch = km.expiresAt.Add(-time.Second)
	km.mu.Unlock()

	_, err = km.GetPublicKey()
	require.NoError(t, err)
	assert.Equal(t, int32(2), fetchCount.Load())
}

func TestKeyManager_ExpiredKeyRefreshFailure(t *testing.T) {
	pub, _ := testKey(t)

	var callCount atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if callCount.Add(1) > 1 {
			http.Error(w, "server error", http.StatusInternalServerError)
			return
		}
		writeKeyResponse(t, w, testKeyResponse(pub, "key-test"))
	}))
	defer server.Close()

	km := NewKeyManager(server.URL, 3600, "", server.Client())

	_, err := km.GetPublicKey()
	require.NoError(t, err)

	// Simulate cache expiry
	km.mu.Lock()
	km.lastFetch = time.Now().Add(-2 * time.Hour)
	km.mu.Unlock()

	// Must not fall back to the stale key
	_, err = km.GetPublicKey()
	assert.ErrorContains(t, err, "public key expired and refresh failed")
}

func TestKeyManager_ServerUnavailable(t *testing.T) {
	km := NewKeyManager("http://localhost:1", 3600, "", &http.Client{Timeout: 1 * time.Second})

	_, err := km.GetPublicKey()
	assert.ErrorContains(t, err, "failed to fetch public key")
}

func TestKeyManager_InvalidAlgorithm(t *testing.T) {
	resp := testKeyResponse(make([]byte, ed25519.PublicKeySize), "key-test")
	resp.Algorithm = "RSA"
	server, _ := keyServer(t, resp)

	km := NewKeyManager(server.URL, 3600, "", server.Client())

	_, err := km.GetPublicKey()
	assert.ErrorContains(t, err, "unsupported algorithm: RSA")
}

func TestKeyManager_InvalidKeySize(t *testing.T) {
	server, _ := keyServer(t, testKeyResponse([]byte("tooshort"), "key-test"))

	km := NewKeyManager(server.URL, 3600, "", server.Client())

	_, err := km.GetPublicKey()
	assert.ErrorContains(t, err, "invalid public key size")
}

func TestKeyManager_GetPublicKeyForKID_CacheHit(t *testing.T) {
	pub, _ := testKey(t)

	server, fetchCount := keyServer(t, testKeyResponse(pub, "key-test-123"))

	km := NewKeyManager(server.URL, 3600, "", server.Client())

	key1, err := km.GetPublicKeyForKID("key-test-123")
	require.NoError(t, err)
	key2, err := km.GetPublicKeyForKID("key-test-123")
	require.NoError(t, err)

	assert.Equal(t, pub, key1)
	assert.Equal(t, key1, key2)
	assert.Equal(t, int32(1), fetchCount.Load())
}

func TestKeyManager_GetPublicKeyForKID_Mismatch(t *testing.T) {
	pub, _ := testKey(t)

	// Alpamon must reject a kid that does not match the active key, even
	// though the refresh returns that same active key.
	server, _ := keyServer(t, testKeyResponse(pub, "key-v2"))

	km := NewKeyManager(server.URL, 3600, "", server.Client())

	_, err := km.GetPublicKeyForKID("key-v2")
	require.NoError(t, err, "expected success when kid matches active key")

	_, err = km.GetPublicKeyForKID("key-v999")
	assert.ErrorContains(t, err, `key "key-v999" is not the active key for this environment`)
}

func TestKeyManager_GetPublicKeyForKID_KeyRotation(t *testing.T) {
	pub1, _ := testKey(t)
	pub2, _ := testKey(t)

	var fetchCount atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		resp := testKeyResponse(pub2, "key-v2")
		if fetchCount.Add(1) == 1 {
			resp = testKeyResponse(pub1, "key-v1")
		}
		writeKeyResponse(t, w, resp)
	}))
	defer server.Close()

	km := NewKeyManager(server.URL, 3600, "", server.Client())

	key1, err := km.GetPublicKeyForKID("key-v1")
	require.NoError(t, err)
	assert.Equal(t, pub1, key1)

	key2, err := km.GetPublicKeyForKID("key-v2")
	require.NoError(t, err)
	assert.Equal(t, pub2, key2)
	assert.Equal(t, int32(2), fetchCount.Load())
}

// The AI server's public-key endpoint reads `env`; a name it does not know is
// ignored and the prod key comes back, which is exactly the mismatch a dev
// agent must not end up with.
func TestKeyManager_AuthEnvQueryParam(t *testing.T) {
	pub, _ := testKey(t)

	// The handler runs on the server's goroutine and the assertions read from
	// the test's, so the query crosses goroutines and needs to be published.
	var lastQuery atomic.Pointer[url.Values]
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		lastQuery.Store(&q)
		writeKeyResponse(t, w, testKeyResponse(pub, "key-dev-1"))
	}))
	defer server.Close()

	km := NewKeyManager(server.URL, 3600, "dev", server.Client())
	_, err := km.GetPublicKey()
	require.NoError(t, err)
	q := lastQuery.Load()
	require.NotNil(t, q)
	assert.Equal(t, "dev", q.Get("env"))

	km2 := NewKeyManager(server.URL, 3600, "", server.Client())
	_, err = km2.GetPublicKey()
	require.NoError(t, err)
	q = lastQuery.Load()
	require.NotNil(t, q)
	assert.NotContains(t, *q, "env")
}

func TestSigningKeyExpiryBounds(t *testing.T) {
	pub, _ := testKey(t)
	resp := testKeyResponse(pub, "test")
	resp.ExpiresAt = "invalid"
	server, _ := keyServer(t, resp)
	invalid := NewKeyManager(server.URL, 7200, "", server.Client())
	_, err := invalid.GetPublicKey()
	require.ErrorContains(t, err, "invalid signing key expiry")
	assert.Nil(t, invalid.publicKey)
	manager := KeyManager{refreshSecs: 7200, lastFetch: time.Now().Add(-time.Hour), expiresAt: new(time.Now().Add(time.Hour))}
	assert.True(t, manager.needsRefresh())
}

func TestSigningKeyRefreshFailure(t *testing.T) {
	pub, _ := testKey(t)
	var attempts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	t.Cleanup(server.Close)
	now := time.Now()
	for _, tc := range []struct {
		name    string
		expiry  *time.Time
		wantKey bool
	}{
		{"valid", new(now.Add(30 * 24 * time.Hour)), true},
		{"expired", new(now.Add(-time.Minute)), false},
		{"no expiry", nil, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			manager := NewKeyManager(server.URL, 3*3600, "", server.Client())
			manager.publicKey, manager.keyID = pub, "test"
			manager.lastFetch, manager.expiresAt = now.Add(-2*time.Hour), tc.expiry
			before := attempts.Load()
			for _, get := range []func() (ed25519.PublicKey, error){
				manager.GetPublicKey,
				func() (ed25519.PublicKey, error) { return manager.GetPublicKeyForKID("test") },
			} {
				key, err := get()
				if tc.wantKey {
					require.NoError(t, err)
					assert.Equal(t, pub, key)
				} else {
					require.ErrorContains(t, err, "503")
					assert.Nil(t, key)
				}
			}
			assert.Equal(t, before+2, attempts.Load())
		})
	}
}

func TestSigningKeyServerExpiry(t *testing.T) {
	pub, _ := testKey(t)
	var logs bytes.Buffer
	original := log.Logger
	log.Logger = zerolog.New(&logs)
	t.Cleanup(func() { log.Logger = original })
	for _, expiry := range []string{`"2000-01-01T00:00:00Z"`, `"0001-01-01T00:00:00Z"`, "null", ""} {
		t.Run(expiry, func(t *testing.T) {
			logs.Reset()
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				field := ""
				if expiry != "" {
					field = `,"expires_at":` + expiry
				}
				_, err := fmt.Fprintf(w, `{"algorithm":"Ed25519","key_id":"test","public_key":%q%s}`, base64.StdEncoding.EncodeToString(pub), field)
				assert.NoError(t, err)
			}))
			t.Cleanup(server.Close)
			manager := NewKeyManager(server.URL, 3600, "", server.Client())
			key, err := manager.GetPublicKey()
			require.NoError(t, err)
			assert.Equal(t, pub, key)
			if expiry == "" || expiry == "null" {
				assert.Nil(t, manager.expiresAt)
				assert.NotContains(t, logs.String(), "signing key expired")
			} else {
				require.NotNil(t, manager.expiresAt)
				assert.Contains(t, logs.String(), "signing key expired at "+strings.Trim(expiry, `"`)+"; the server has not rotated it")
			}
		})
	}
}

type signingRoundTripper func(*http.Request) (*http.Response, error)

func (f signingRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestConcurrentSigningKeyLookupsShareFailedRefresh(t *testing.T) {
	pub, _ := testKey(t)
	synctest.Test(t, func(t *testing.T) {
		started := make(chan struct{})
		release := make(chan struct{})
		var attempts atomic.Int32
		client := &http.Client{Transport: signingRoundTripper(func(req *http.Request) (*http.Response, error) {
			if attempts.Add(1) == 1 {
				close(started)
			}
			<-release
			return nil, fmt.Errorf("signing key service unavailable")
		})}
		manager := NewKeyManager("https://example.invalid", 3600, "", client)
		manager.publicKey, manager.keyID = pub, "test"
		manager.lastFetch = time.Now().Add(-time.Hour)
		manager.expiresAt = new(time.Now().Add(time.Hour))

		first := make(chan ed25519.PublicKey, 1)
		second := make(chan ed25519.PublicKey, 1)
		go func() {
			key, err := manager.GetPublicKey()
			assert.NoError(t, err)
			first <- key
		}()
		<-started
		go func() {
			key, err := manager.GetPublicKeyForKID("test")
			assert.NoError(t, err)
			second <- key
		}()
		synctest.Wait()
		close(release)
		assert.Equal(t, pub, <-first)
		assert.Equal(t, pub, <-second)
		assert.EqualValues(t, 1, attempts.Load())

		time.Sleep(time.Hour)
		key, err := manager.GetPublicKeyForKID("test")
		require.ErrorContains(t, err, "signing key service unavailable")
		assert.Nil(t, key)
	})
}
