package signing

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

// maxResponseSize limits the public key response body to prevent
// excessive memory usage from a misbehaving server.
const maxResponseSize = 16 * 1024 // 16 KB

// publicKeyResponse represents the response from GET /api/commands/public-key/
type publicKeyResponse struct {
	Algorithm string `json:"algorithm"`
	PublicKey string `json:"public_key"`
	KeyID     string `json:"key_id"`
	ValidFrom string `json:"valid_from"`
	ExpiresAt string `json:"expires_at,omitempty"`
}

// fetchTimeout is the timeout for public key HTTP requests.
const fetchTimeout = 10 * time.Second

// KeyManager fetches and caches the Ed25519 public key from the AI server.
type KeyManager struct {
	mu          sync.RWMutex
	publicKey   ed25519.PublicKey
	keyID       string
	lastFetch   time.Time
	expiresAt   time.Time
	refreshSecs int
	aiBaseURL   string
	client      *http.Client

	// refreshMu serializes refresh calls to prevent concurrent fetch bursts
	refreshMu sync.Mutex
}

// NewKeyManager creates a key manager that fetches from the AI server.
func NewKeyManager(aiBaseURL string, refreshSecs int, client *http.Client) *KeyManager {
	if client == nil {
		client = http.DefaultClient
	}
	return &KeyManager{
		aiBaseURL:   strings.TrimRight(aiBaseURL, "/"),
		refreshSecs: refreshSecs,
		client:      client,
	}
}

// GetPublicKey returns a copy of the cached public key, refreshing if stale.
func (m *KeyManager) GetPublicKey() (ed25519.PublicKey, error) {
	m.mu.RLock()
	if m.publicKey != nil && !m.isExpired() {
		key := copyKey(m.publicKey)
		m.mu.RUnlock()
		return key, nil
	}
	m.mu.RUnlock()

	if err := m.Refresh(); err != nil {
		m.mu.RLock()
		defer m.mu.RUnlock()
		if m.publicKey != nil && !m.isExpired() {
			return copyKey(m.publicKey), nil
		}
		return nil, fmt.Errorf("public key expired and refresh failed: %w", err)
	}

	m.mu.RLock()
	defer m.mu.RUnlock()
	return copyKey(m.publicKey), nil
}

// GetPublicKeyForKID returns the cached key if the kid matches and the key is not expired.
// If the kid doesn't match, it fetches that specific key by key_id from the AI server.
// This handles both key rotation and cross-environment scenarios (dev/prod).
func (m *KeyManager) GetPublicKeyForKID(kid string) (ed25519.PublicKey, error) {
	m.mu.RLock()
	if m.publicKey != nil && m.keyID == kid && !m.isExpired() {
		key := copyKey(m.publicKey)
		m.mu.RUnlock()
		return key, nil
	}
	m.mu.RUnlock()

	// Fetch the specific key by key_id (handles rotation + cross-env)
	key, err := m.fetchKeyByKID(kid)
	if err != nil {
		m.mu.RLock()
		defer m.mu.RUnlock()
		if m.publicKey != nil && m.keyID == kid && !m.isExpired() {
			return copyKey(m.publicKey), nil
		}
		return nil, fmt.Errorf("failed to fetch key for kid %q: %w", kid, err)
	}
	return key, nil
}

// isExpired reports whether the cached key should be refreshed.
// Must be called with m.mu held (read or write).
func (m *KeyManager) isExpired() bool {
	// If AI server provided expires_at, use it
	if !m.expiresAt.IsZero() {
		return time.Now().After(m.expiresAt)
	}
	// Fall back to TTL-based refresh
	return time.Since(m.lastFetch) >= time.Duration(m.refreshSecs)*time.Second
}

func copyKey(key ed25519.PublicKey) ed25519.PublicKey {
	cp := make(ed25519.PublicKey, len(key))
	copy(cp, key)
	return cp
}

// Refresh fetches the latest public key from the AI server.
// Only one refresh runs at a time; concurrent callers wait for the in-flight result.
// If the cache is still valid (another goroutine refreshed), this is a no-op.
func (m *KeyManager) Refresh() error {
	m.refreshMu.Lock()
	defer m.refreshMu.Unlock()

	// Double-check: another goroutine may have refreshed while we waited
	m.mu.RLock()
	if m.publicKey != nil && !m.isExpired() {
		m.mu.RUnlock()
		return nil
	}
	m.mu.RUnlock()

	return m.fetchKeyLocked()
}

// ForceRefresh fetches the public key from the AI server unconditionally,
// regardless of whether the cached key is still valid. Use this when
// signature verification fails and a key rotation may have occurred.
func (m *KeyManager) ForceRefresh() error {
	return m.fetchKey()
}

// fetchKey acquires the refresh lock and fetches unconditionally.
// Used by GetPublicKeyForKID when kid doesn't match (key may not be expired).
func (m *KeyManager) fetchKey() error {
	m.refreshMu.Lock()
	defer m.refreshMu.Unlock()
	return m.fetchKeyLocked()
}

// fetchKeyByKID fetches a specific public key by key_id from the AI server.
// Unlike fetchKeyLocked (which gets the active key), this queries by key_id
// to support key rotation and cross-environment (dev/prod) key lookup.
// The result is NOT cached — it is returned directly.
func (m *KeyManager) fetchKeyByKID(kid string) (ed25519.PublicKey, error) {
	url := m.aiBaseURL + "/api/commands/public-key/?key_id=" + kid

	ctx, cancel := context.WithTimeout(context.Background(), fetchTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := m.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch public key for kid %q: %w", kid, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("public key endpoint returned status %d for kid %q", resp.StatusCode, kid)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize+1))
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}
	if int64(len(body)) > maxResponseSize {
		return nil, fmt.Errorf("public key response too large (>%d bytes)", maxResponseSize)
	}

	var keyResp publicKeyResponse
	if err := json.Unmarshal(body, &keyResp); err != nil {
		return nil, fmt.Errorf("failed to parse public key response: %w", err)
	}

	if keyResp.Algorithm != "Ed25519" {
		return nil, fmt.Errorf("unsupported algorithm: %s", keyResp.Algorithm)
	}

	keyBytes, err := base64.StdEncoding.DecodeString(keyResp.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode public key: %w", err)
	}

	if len(keyBytes) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid public key size: got %d, want %d", len(keyBytes), ed25519.PublicKeySize)
	}

	return ed25519.PublicKey(keyBytes), nil
}

// fetchKeyLocked performs the actual HTTP fetch. Must be called with refreshMu held.
func (m *KeyManager) fetchKeyLocked() error {
	url := m.aiBaseURL + "/api/commands/public-key/"

	ctx, cancel := context.WithTimeout(context.Background(), fetchTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := m.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to fetch public key: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("public key endpoint returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize+1))
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}
	if int64(len(body)) > maxResponseSize {
		return fmt.Errorf("public key response too large (>%d bytes)", maxResponseSize)
	}

	var keyResp publicKeyResponse
	if err := json.Unmarshal(body, &keyResp); err != nil {
		return fmt.Errorf("failed to parse public key response: %w", err)
	}

	if keyResp.Algorithm != "Ed25519" {
		return fmt.Errorf("unsupported algorithm: %s", keyResp.Algorithm)
	}

	if keyResp.KeyID == "" {
		return errors.New("AI server returned empty key_id")
	}

	keyBytes, err := base64.StdEncoding.DecodeString(keyResp.PublicKey)
	if err != nil {
		return fmt.Errorf("failed to decode public key: %w", err)
	}

	if len(keyBytes) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid public key size: got %d, want %d", len(keyBytes), ed25519.PublicKeySize)
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	m.publicKey = ed25519.PublicKey(keyBytes)
	m.keyID = keyResp.KeyID
	m.lastFetch = time.Now()

	if keyResp.ExpiresAt != "" {
		if t, err := time.Parse(time.RFC3339, keyResp.ExpiresAt); err == nil {
			m.expiresAt = t
			log.Debug().Str("key_id", keyResp.KeyID).Time("expires_at", t).Msg("Public signing key refreshed.")
		} else {
			log.Warn().Str("expires_at", keyResp.ExpiresAt).Msg("Failed to parse expires_at, falling back to TTL-based refresh.")
			m.expiresAt = time.Time{}
		}
	} else {
		m.expiresAt = time.Time{}
		log.Debug().Str("key_id", keyResp.KeyID).Msg("Public signing key refreshed.")
	}

	return nil
}
