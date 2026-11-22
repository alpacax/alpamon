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
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

// devDomain is the dev workspace domain. Every workspace has its own
// subdomain, so an agent's configured URL is <workspace>.dev.alpacon.io, never
// the bare domain.
const devDomain = "dev.alpacon.io"

// ResolveAuthEnv determines the auth environment from the alpacon server URL.
// dev.alpacon.io and any subdomain of it → "dev", everything else → "" (prod
// default). This lets alpamon derive its environment from trusted local config
// rather than trusting the key_id provided by the relay (alpacon-server).
//
// NOTE: When adding new environments (e.g. staging), add a corresponding
// hostname check below and update TestResolveAuthEnv.
func ResolveAuthEnv(serverURL string) string {
	u, err := url.Parse(serverURL)
	if err != nil {
		return ""
	}
	// A trailing-dot FQDN keeps its dot in Hostname(); it names the same host.
	host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	if host == devDomain || strings.HasSuffix(host, "."+devDomain) {
		return "dev"
	}
	return ""
}

// IsLocalEnv reports whether the server URL points to a local development
// environment (localhost, 127.0.0.1, etc.) where the AI signing server is
// unavailable and command signing cannot work.
func IsLocalEnv(serverURL string) bool {
	u, err := url.Parse(serverURL)
	if err != nil {
		return false
	}
	host := u.Hostname()
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}

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
	expiresAt   *time.Time
	refreshSecs int
	aiBaseURL   string
	authEnv     string // "dev" or "" (prod); derived from alpacon server URL
	client      *http.Client

	refreshMu           sync.Mutex
	inFlight            *keyRefresh
	lastRotationAttempt time.Time
}

type keyRefresh struct {
	done chan struct{}
	err  error
}

// NewKeyManager creates a key manager that fetches from the AI server.
// authEnv is the environment identifier (e.g. "dev") derived from the alpacon
// server URL via ResolveAuthEnv. It is used to scope key fetches so that
// alpamon only trusts keys for its own environment.
func NewKeyManager(aiBaseURL string, refreshSecs int, authEnv string, client *http.Client) *KeyManager {
	if client == nil {
		client = http.DefaultClient
	}
	return &KeyManager{
		aiBaseURL:   strings.TrimRight(aiBaseURL, "/"),
		refreshSecs: refreshSecs,
		authEnv:     authEnv,
		client:      client,
	}
}

// GetPublicKey returns a copy of the cached public key, refreshing if stale.
func (m *KeyManager) GetPublicKey() (ed25519.PublicKey, error) {
	m.mu.RLock()
	if m.publicKey != nil && !m.needsRefresh() {
		key := copyKey(m.publicKey)
		m.mu.RUnlock()
		return key, nil
	}
	m.mu.RUnlock()

	if err := m.Refresh(); err != nil {
		m.mu.RLock()
		defer m.mu.RUnlock()
		if m.canUseCachedKey() {
			return copyKey(m.publicKey), nil
		}
		return nil, fmt.Errorf("public key expired and refresh failed: %w", err)
	}

	m.mu.RLock()
	defer m.mu.RUnlock()
	return copyKey(m.publicKey), nil
}

// GetPublicKeyForKID returns the cached key if its kid matches.
// If the kid doesn't match (possible key rotation), it refreshes the active
// key for this environment from the AI server. The key_id from the command is
// used only as a cache-staleness hint — never as a query parameter — so that
// a compromised relay cannot direct alpamon to fetch an arbitrary key.
func (m *KeyManager) GetPublicKeyForKID(kid string) (ed25519.PublicKey, error) {
	m.mu.RLock()
	if m.publicKey != nil && m.keyID == kid && !m.needsRefresh() {
		key := copyKey(m.publicKey)
		m.mu.RUnlock()
		return key, nil
	}
	m.mu.RUnlock()

	if err := m.refresh(kid, kid == ""); err != nil {
		m.mu.RLock()
		defer m.mu.RUnlock()
		if m.keyID == kid && m.canUseCachedKey() {
			return copyKey(m.publicKey), nil
		}
		return nil, fmt.Errorf("failed to refresh key for kid %q: %w", kid, err)
	}

	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.publicKey != nil && m.keyID == kid {
		return copyKey(m.publicKey), nil
	}
	return nil, fmt.Errorf("key %q is not the active key for this environment (active: %q)", kid, m.keyID)
}

// Must be called with m.mu held (read or write).
func (m *KeyManager) needsRefresh() bool {
	now := time.Now()
	return (m.expiresAt != nil && !now.Before(*m.expiresAt)) ||
		now.Sub(m.lastFetch) >= min(time.Duration(m.refreshSecs)*time.Second, time.Hour)
}

// The configured TTL still limits fallback for keys without a server expiry.
// Must be called with m.mu held.
func (m *KeyManager) canUseCachedKey() bool {
	if m.publicKey == nil {
		return false
	}
	if m.expiresAt == nil {
		return time.Since(m.lastFetch) < time.Duration(m.refreshSecs)*time.Second
	}
	return time.Now().Before(*m.expiresAt)
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
	return m.refresh("", false)
}

// RefreshAndGet fetches the active key unconditionally (ignoring cache TTL)
// and returns it. Used for one-time retry on signature mismatch when the
// command has no key_id. This is env-scoped and does not accept any
// relay-provided key identifier.
func (m *KeyManager) RefreshAndGet() (ed25519.PublicKey, error) {
	if err := m.refresh("", true); err != nil {
		return nil, err
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return copyKey(m.publicKey), nil
}

func (m *KeyManager) refresh(kid string, force bool) error {
	m.refreshMu.Lock()

	m.mu.RLock()
	fresh := m.publicKey != nil && !m.needsRefresh()
	rotation := kid != "" && m.keyID != kid
	m.mu.RUnlock()
	if !force && fresh && !rotation {
		m.refreshMu.Unlock()
		return nil
	}
	if current := m.inFlight; current != nil {
		m.refreshMu.Unlock()
		<-current.done
		return current.err
	}

	// Limit requests made solely to discover a new KID. Cache expiry still
	// requires a refresh, and concurrent callers can share an in-flight fetch.
	if fresh && rotation {
		now := time.Now()
		if now.Sub(m.lastRotationAttempt) < time.Second {
			m.refreshMu.Unlock()
			return nil
		}
		m.lastRotationAttempt = now
	}
	current := &keyRefresh{done: make(chan struct{})}
	m.inFlight = current
	m.refreshMu.Unlock()

	current.err = m.fetchKey()

	m.refreshMu.Lock()
	m.inFlight = nil
	close(current.done)
	m.refreshMu.Unlock()
	return current.err
}

func (m *KeyManager) fetchKey() error {
	fetchURL := m.aiBaseURL + "/api/commands/public-key/"
	if m.authEnv != "" {
		fetchURL += "?env=" + url.QueryEscape(m.authEnv)
	}

	ctx, cancel := context.WithTimeout(context.Background(), fetchTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fetchURL, nil)
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

	var keyResp struct {
		publicKeyResponse
		Expiry json.RawMessage `json:"expires_at"`
	}
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
	now := time.Now()
	var expiry *time.Time
	if keyResp.Expiry != nil {
		if err := json.Unmarshal(keyResp.Expiry, &expiry); err != nil {
			return fmt.Errorf("invalid signing key expiry: %w", err)
		}
		if expiry != nil && !expiry.After(now) {
			log.Warn().Msgf("signing key expired at %s; the server has not rotated it", expiry.Format(time.RFC3339))
		}
	}
	m.publicKey = ed25519.PublicKey(keyBytes)
	m.keyID = keyResp.KeyID
	m.lastFetch = now
	m.expiresAt = expiry
	log.Debug().Str("key_id", keyResp.KeyID).Msg("Public signing key refreshed.")

	return nil
}
