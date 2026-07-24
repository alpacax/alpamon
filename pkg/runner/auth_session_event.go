package runner

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/alpacax/alpamon/v2/internal/retry"
	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
)

// nonAlpaconAccessEventURL is the alpacon-server ingestion endpoint for
// non-Alpacon access events. Phase 2 (server) must implement this path;
// until then alpamon treats 404 as "not deployed" and drops the event.
const nonAlpaconAccessEventURL = "/api/events/access/"

// errAccessEndpointNotDeployed marks the expected steady state where
// alpacon-server has not yet implemented the access event endpoint
// (Phase 2 not deployed): the POST returns 404. It is the normal
// condition until the server rolls out, so it is logged quietly rather
// than as an emit failure. Matched via errors.Is because retry.Retry
// unwraps the PermanentError and returns this sentinel directly.
var errAccessEndpointNotDeployed = errors.New("access event endpoint not available (404)")

// errAccessEventRejected marks a 4xx other than 404: the server refused this
// event (bad credentials, revoked permission, schema mismatch). Retrying
// cannot change the outcome, so the emit is abandoned immediately.
var errAccessEventRejected = errors.New("access event rejected")

// SessionEventRequest is sent by alpamon-pam's pam_sm_open_session hook
// over auth.sock whenever a PAM session opens on a hooked service
// (sshd, login, su). rhost/tty are empty for sessions without them
// (e.g. local console logins have no rhost).
type SessionEventRequest struct {
	Type     string `json:"type"`
	Username string `json:"username"`
	Service  string `json:"service"`
	RHost    string `json:"rhost,omitempty"`
	TTY      string `json:"tty,omitempty"`
	PID      int    `json:"pid"`
	PPID     int    `json:"ppid"`
}

// SessionEventResponse acks a session_event so the PAM module never sees
// an abrupt disconnect. It carries no decision: detection is fire-and-
// forget and must never influence the login outcome.
type SessionEventResponse struct {
	Type     string `json:"type"`
	Received bool   `json:"received"`
}

// NonAlpaconAccessEvent is the payload POSTed to alpacon-server when a
// session opens outside the Alpacon paths (direct SSH, scp/sftp, local
// console, su from a non-Alpacon shell).
type NonAlpaconAccessEvent struct {
	// EventID makes delivery idempotent. Post is retried on transport
	// errors and 5xx, which cannot distinguish "the server never got it"
	// from "the server stored it but the reply was lost" — without a
	// stable id per session, that second case records the same login
	// twice. The server treats (server, event_id) as unique.
	EventID   string    `json:"event_id"`
	Username  string    `json:"username"`
	Service   string    `json:"service"`
	RHost     string    `json:"rhost,omitempty"`
	TTY       string    `json:"tty,omitempty"`
	PID       int       `json:"pid"`
	PPID      int       `json:"ppid"`
	Timestamp time.Time `json:"timestamp"`
}

// resolveSessionEvent decides whether req represents a non-Alpacon
// session. It reuses the sudo-approval lookup: the caller's session id
// (shared by every process in a Websh or Command session) or its direct
// parent pid resolving to a tracker entry means the session originated
// from Alpacon — e.g. su executed inside a Websh terminal — and must be
// suppressed. The second return value reports whether to emit.
func (am *AuthManager) resolveSessionEvent(req SessionEventRequest) (NonAlpaconAccessEvent, bool) {
	sid, sidOK := sessionID(req.PID)
	am.mu.RLock()
	session, exists := am.lookupSessionLocked(sid, sidOK, req.PPID)
	am.mu.RUnlock()

	if exists {
		log.Debug().
			Str("kind", session.effectiveKind()).
			Str("session_id", session.SessionID).
			Str("command_id", session.CommandID).
			Int("pid", req.PID).
			Msg("Session event suppressed: Alpacon-originated session")
		return NonAlpaconAccessEvent{}, false
	}

	return NonAlpaconAccessEvent{
		// Generated once here, so every retry of the same session
		// carries the same id.
		EventID:   uuid.NewString(),
		Username:  req.Username,
		Service:   req.Service,
		RHost:     req.RHost,
		TTY:       req.TTY,
		PID:       req.PID,
		PPID:      req.PPID,
		Timestamp: time.Now().UTC(),
	}, true
}

// handleSessionEvent processes a session_event from the PAM session
// hook. The ack is written before any server round-trip so PAM (and
// thus sshd) never waits on emission; the POST runs on its own
// goroutine. Fail-open: every path answers the socket.
func (am *AuthManager) handleSessionEvent(data []byte, unixConn net.Conn) {
	defer func() { _ = unixConn.Close() }()

	var req SessionEventRequest
	if err := json.Unmarshal(data, &req); err != nil {
		log.Warn().Err(err).Msg("Invalid session_event request")
		am.sendSessionEventResponse(unixConn, false)
		return
	}

	// A well-formed envelope can still carry a useless event (missing user
	// or pid). Reject it here rather than forwarding a blank audit record
	// upstream; the ack still goes out so PAM never waits on us.
	if req.Username == "" || req.Service == "" || req.PID <= 0 {
		log.Warn().
			Str("username", req.Username).
			Str("service", req.Service).
			Int("pid", req.PID).
			Msg("Incomplete session_event request; dropping")
		am.sendSessionEventResponse(unixConn, false)
		return
	}

	event, emit := am.resolveSessionEvent(req)

	am.sendSessionEventResponse(unixConn, true)

	am.mu.RLock()
	detect := am.detectLocalAccess
	emitFn := am.emitAccessEventFn
	am.mu.RUnlock()

	if !emit || !detect {
		return
	}
	if emitFn == nil {
		emitFn = am.emitAccessEvent
	}

	// Bound in-flight emit goroutines: each can hold up to authRetryTimeout
	// of retry against an unreachable server, so a login burst could
	// otherwise spawn goroutines without limit. Acquire a slot without
	// blocking (the ack was already sent above); drop the event if the
	// budget is exhausted.
	select {
	case am.emitSem <- struct{}{}:
	default:
		log.Debug().
			Str("username", event.Username).
			Str("service", event.Service).
			Msg("access event dropped: emit concurrency limit reached")
		return
	}
	go func() {
		defer func() { <-am.emitSem }()
		emitFn(event)
	}()
}

func (am *AuthManager) sendSessionEventResponse(conn net.Conn, received bool) {
	response := SessionEventResponse{
		Type:     "session_event_response",
		Received: received,
	}

	responseJSON, err := json.Marshal(response)
	if err != nil {
		log.Error().Err(err).Msg("Failed to marshal session_event_response")
		return
	}

	if _, err := conn.Write(responseJSON); err != nil {
		log.Warn().Err(err).Msg("Failed to send session_event_response")
	}
}

// emitAccessEvent POSTs a non-Alpacon access event to alpacon-server
// with bounded best-effort retry (same backoff envelope as the sudo
// approval path). It runs on its own goroutine; failures are logged and
// dropped so detection never blocks logins. A 404 means the server does
// not implement the endpoint yet (Phase 2 not deployed) and is not
// retried.
func (am *AuthManager) emitAccessEvent(event NonAlpaconAccessEvent) {
	if am.session == nil {
		log.Warn().Msg("HTTP session not available; dropping access event")
		return
	}

	baseCtx := am.ctx
	if baseCtx == nil {
		baseCtx = context.Background()
	}
	ctx, cancel := context.WithTimeout(baseCtx, authRetryTimeout)
	defer cancel()

	b := &retry.ExponentialBackoff{
		InitialInterval: authRetryInitialInterval,
		MaxInterval:     authRetryMaxInterval,
		MaxElapsedTime:  authRetryTimeout,
	}

	err := retry.Retry(ctx, b, func() error {
		_, statusCode, err := am.session.Post(nonAlpaconAccessEventURL, event, 10)
		if err != nil {
			return err
		}
		if statusCode == http.StatusNotFound {
			return retry.Permanent(errAccessEndpointNotDeployed)
		}
		// 4xx means the server rejected this event (bad token, revoked
		// permission, schema mismatch); retrying cannot change the verdict
		// and would pin an emit slot for the whole backoff window, dropping
		// the events that arrive meanwhile. Fail fast instead.
		if statusCode >= 400 && statusCode < 500 {
			return retry.Permanent(fmt.Errorf(
				"%w with status code: %d", errAccessEventRejected, statusCode))
		}
		if statusCode < 200 || statusCode >= 300 {
			return fmt.Errorf("access event failed with status code: %d", statusCode)
		}
		return nil
	})
	if err != nil {
		if errors.Is(err, errAccessEndpointNotDeployed) {
			// Expected until Phase 2 (server endpoint) ships; not a
			// failure, so log quietly and drop.
			log.Debug().
				Str("username", event.Username).
				Str("service", event.Service).
				Msg("Access event endpoint not deployed (404); dropping event")
			return
		}
		if errors.Is(err, errAccessEventRejected) {
			log.Warn().Err(err).
				Str("username", event.Username).
				Str("service", event.Service).
				Msg("Access event rejected by server; dropping event")
			return
		}
		log.Warn().Err(err).
			Str("username", event.Username).
			Str("service", event.Service).
			Msg("Failed to emit non-Alpacon access event: server unreachable")
	}
}
