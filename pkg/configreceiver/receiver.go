// Package configreceiver implements the agent side of the pull-based
// plugin-config flow defined by alpacon-server. Plugins (dhcp, dns,
// proxy, …) embed a Receiver in their WS command loop and supply an
// Applier; the package owns the fetch / verify / report machinery
// that every plugin needs identically.
//
// Flow:
//
//  1. alpacon-server emits a “config_updated“ WS event with the
//     “plugin_config_id“ of the freshly-rendered config row.
//  2. The plugin receives that event and hands it to Receiver.Handle.
//  3. Receiver fetches the body via “GET /api/plugins/configs/{id}/“,
//     verifies the sha256 hash matches what the event reported, then
//     decodes the standard “{files, metadata}“ envelope and calls
//     the plugin-supplied Applier.
//  4. Receiver reports success or failure via
//     “POST /api/plugins/configs/{id}/applied/“ so the server can
//     tell which version is live (drift detection / audit).
//
// Lives under github.com/alpacax/alpamon because every plugin already
// depends on alpamon; adding a separate "alpacon-plugin-sdk" repo
// would add release-coordination overhead with no offsetting benefit.
package configreceiver

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/alpacax/alpamon/v2/pkg/scheduler"
	"github.com/rs/zerolog/log"
)

const (
	fetchURLFmt   = "/api/plugins/configs/%s/"
	appliedURLFmt = "/api/plugins/configs/%s/applied/"
	// requestTimeout caps each REST call. scheduler.Session.do
	// multiplies whatever Duration value is passed in by
	// ``time.Second`` (pkg/scheduler/session.go:113), so the bare
	// literal ``30`` here resolves to 30 seconds end-to-end — passing
	// ``30 * time.Second`` would compound the multiplier and overflow
	// int64. The type stays ``time.Duration`` only because that's the
	// signature scheduler.Session exposes; the value semantics are
	// "count of seconds".
	requestTimeout time.Duration = 30
)

// Envelope is the standardised config-text shape the server emits.
// “files“ carries one or more files keyed by on-disk name; metadata
// is plugin-specific structured data (raw JSON so plugins decode
// only the keys they understand).
type Envelope struct {
	Files    map[string]string          `json:"files"`
	Metadata map[string]json.RawMessage `json:"metadata"`
}

// configResponse mirrors PluginConfigDetailSerializer from alpacon-server.
type configResponse struct {
	ID         string `json:"id"`
	PluginType string `json:"plugin_type"`
	ServerID   string `json:"server_id"`
	Version    uint32 `json:"version"`
	ConfigHash string `json:"config_hash"`
	ConfigText string `json:"config_text"`
}

// Applier installs a fetched config on disk and restarts/reloads the
// service. Errors returned from Apply are reported verbatim to the
// server so administrators can debug from the alpacon UI.
type Applier interface {
	Apply(ctx context.Context, env Envelope) error
}

// Receiver wires REST fetch + hash check + Applier dispatch into the
// plugin's WS command loop.
//
// applyMu serialises Handle calls so two “config_updated“ events
// arriving in quick succession cannot have their applies interleave
// (older config finishing after newer would leave the plugin in a
// stale state). Apply itself can be long-running (file writes +
// service reload) and is per-Receiver, so a plain mutex is enough.
type Receiver struct {
	Session *scheduler.Session
	Applier Applier
	applyMu sync.Mutex
}

// Handle is the entry point called from the WS command switch when a
// “config_updated“ event arrives. Safe to call from a fresh goroutine:
// concurrent invocations are serialised by applyMu so applies run in
// the order their config_updated events landed.
func (r *Receiver) Handle(ctx context.Context, pluginConfigID string) {
	if r == nil || r.Session == nil || r.Applier == nil {
		log.Error().
			Str("id", pluginConfigID).
			Msg("configreceiver.Receiver not fully wired (nil Session or Applier); dropping config_updated")
		return
	}

	r.applyMu.Lock()
	defer r.applyMu.Unlock()

	cfg, err := r.fetch(pluginConfigID)
	if err != nil {
		log.Error().Err(err).Str("id", pluginConfigID).Msg("Failed to fetch plugin config")
		r.reportError(pluginConfigID, "fetch failed: "+err.Error())
		return
	}

	if actual := sha256hex(cfg.ConfigText); actual != cfg.ConfigHash {
		log.Error().
			Str("id", pluginConfigID).
			Str("expected", cfg.ConfigHash).
			Str("actual", actual).
			Msg("Config hash mismatch")
		r.reportError(pluginConfigID, "hash mismatch")
		return
	}

	var env Envelope
	if err := json.Unmarshal([]byte(cfg.ConfigText), &env); err != nil {
		log.Error().Err(err).Msg("Failed to decode config envelope")
		r.reportError(pluginConfigID, "envelope decode: "+err.Error())
		return
	}

	if err := r.Applier.Apply(ctx, env); err != nil {
		log.Error().Err(err).Msg("Applier returned error")
		r.reportError(pluginConfigID, err.Error())
		return
	}

	log.Info().
		Str("id", pluginConfigID).
		Uint32("version", cfg.Version).
		Msg("Plugin config applied")
	r.reportApplied(pluginConfigID, cfg.ConfigHash)
}

func (r *Receiver) fetch(id string) (*configResponse, error) {
	url := fmt.Sprintf(fetchURLFmt, id)
	body, statusCode, err := r.Session.Get(url, requestTimeout)
	if err != nil {
		return nil, err
	}
	if statusCode < 200 || statusCode >= 300 {
		// Cap the response body included in the error. Without a
		// cap a 50 MB upstream error page would land in alpacon-
		// server's DB and the local log; the truncated preview is
		// enough to diagnose the typical 4xx/5xx text response.
		return nil, fmt.Errorf("unexpected status %d from %s: %s",
			statusCode, url, truncateUTF8(string(body), maxBodyPreviewBytes))
	}
	var resp configResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	return &resp, nil
}

// applySuccess / applyError are the two POST bodies for the applied endpoint.
// Fields are declared in the alphabetical key order json.Marshal emits for a
// map, so the wire format is byte-identical to the prior map literals.
type applySuccess struct {
	AppliedHash string `json:"applied_hash"`
	Success     bool   `json:"success"`
}

type applyError struct {
	Error   string `json:"error"`
	Success bool   `json:"success"`
}

func (r *Receiver) reportApplied(id, hash string) {
	r.post(id, applySuccess{Success: true, AppliedHash: hash})
}

// maxReportedErrorBytes caps the error string posted to the server.
// Applier and fetch errors can include full upstream response bodies
// or large stack traces; truncating prevents DB bloat and accidental
// secret leakage via log/error fields.
//
// Byte-based cap rather than rune-based: “[]rune(s)“ allocates a
// whole rune slice for the entire input, which is wasteful on a 10
// MiB error string. “truncateUTF8“ walks the byte budget and only
// pulls back to the nearest rune boundary, so the truncation never
// produces an invalid UTF-8 sequence either.
const maxReportedErrorBytes = 2048

// maxBodyPreviewBytes caps the upstream response body folded into a
// fetch error. 512 bytes is enough to identify a 4xx/5xx response
// shape without flooding the receiver's log + server DB.
const maxBodyPreviewBytes = 512

// truncateUTF8 caps s at maxBytes bytes, then pulls the boundary
// back to the previous rune start so the result is valid UTF-8.
// Returns the original string when len(s) <= maxBytes.
func truncateUTF8(s string, maxBytes int) string {
	if len(s) <= maxBytes {
		return s
	}
	end := maxBytes
	for end > 0 && !utf8.RuneStart(s[end]) {
		end--
	}
	return s[:end] + "...(truncated)"
}

func (r *Receiver) reportError(id, errMsg string) {
	r.post(id, applyError{Success: false, Error: truncateUTF8(errMsg, maxReportedErrorBytes)})
}

func (r *Receiver) post(id string, payload any) {
	url := fmt.Sprintf(appliedURLFmt, id)
	body, statusCode, err := r.Session.Post(url, payload, requestTimeout)
	if err != nil {
		log.Error().Err(err).Str("id", id).Msg("Failed to report config apply")
		return
	}
	if statusCode < 200 || statusCode >= 300 {
		log.Error().
			Int("status", statusCode).
			Str("id", id).
			Str("body", string(body)).
			Msg("Unexpected status reporting config apply")
	}
}

func sha256hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}
