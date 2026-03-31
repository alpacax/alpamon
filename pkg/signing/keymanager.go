package signing

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

// publicKeyResponse represents the response from GET /api/commands/public-key/
type publicKeyResponse struct {
	Algorithm string `json:"algorithm"`
	PublicKey string `json:"public_key"`
	KeyID     string `json:"key_id"`
	ValidFrom string `json:"valid_from"`
}

// KeyManager fetches and caches the Ed25519 public key from the AI server.
type KeyManager struct {
	mu             sync.RWMutex
	publicKey      ed25519.PublicKey
	keyID          string
	lastFetch      time.Time
	refreshSecs    int
	aiBaseURL      string
	client         *http.Client
	fetchTimeout   time.Duration
}

// NewKeyManager creates a key manager that fetches from the AI server.
func NewKeyManager(aiBaseURL string, refreshSecs int, client *http.Client) *KeyManager {
	if client == nil {
		client = http.DefaultClient
	}
	return &KeyManager{
		aiBaseURL:    strings.TrimRight(aiBaseURL, "/"),
		refreshSecs:  refreshSecs,
		client:       client,
		fetchTimeout: 10 * time.Second,
	}
}

// GetPublicKey returns a copy of the cached public key, refreshing if stale.
func (m *KeyManager) GetPublicKey() (ed25519.PublicKey, error) {
	m.mu.RLock()
	if m.publicKey != nil && time.Since(m.lastFetch) < time.Duration(m.refreshSecs)*time.Second {
		key := copyKey(m.publicKey)
		m.mu.RUnlock()
		return key, nil
	}
	m.mu.RUnlock()

	if err := m.Refresh(); err != nil {
		m.mu.RLock()
		defer m.mu.RUnlock()
		if m.publicKey != nil {
			return copyKey(m.publicKey), nil
		}
		return nil, err
	}

	m.mu.RLock()
	defer m.mu.RUnlock()
	return copyKey(m.publicKey), nil
}

func copyKey(key ed25519.PublicKey) ed25519.PublicKey {
	cp := make(ed25519.PublicKey, len(key))
	copy(cp, key)
	return cp
}

// Refresh fetches the latest public key from the AI server.
func (m *KeyManager) Refresh() error {
	url := m.aiBaseURL + "/api/commands/public-key/"

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	client := &http.Client{
		Transport:     m.client.Transport,
		CheckRedirect: m.client.CheckRedirect,
		Jar:           m.client.Jar,
		Timeout:       m.fetchTimeout,
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to fetch public key: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("public key endpoint returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}

	var keyResp publicKeyResponse
	if err := json.Unmarshal(body, &keyResp); err != nil {
		return fmt.Errorf("failed to parse public key response: %w", err)
	}

	if keyResp.Algorithm != "Ed25519" {
		return fmt.Errorf("unsupported algorithm: %s", keyResp.Algorithm)
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

	log.Debug().Str("key_id", keyResp.KeyID).Msg("Public signing key refreshed.")

	return nil
}
