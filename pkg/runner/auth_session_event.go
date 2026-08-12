package runner

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/alpacax/alpamon/v2/internal/retry"
	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
)

// lastEmitDropWarn holds the Unix second of the last Warn-level emit-drop log,
// so a sustained outage rate-limits the Warn instead of flooding.
var lastEmitDropWarn atomic.Int64

// nonAlpaconAccessEventURL is the alpacon-server ingestion endpoint for
// non-Alpacon access events. Phase 2 (server) must implement this path;
// until then alpamon treats 404 as "not deployed" and drops the event.
const nonAlpaconAccessEventURL = "/api/events/access/"

// errAccessEndpointNotDeployed marks the expected steady state where
// alpacon-server has not yet implemented the access event endpoint
// (Phase 2 not deployed): the POST returns 404. It is the normal
// condition until the server rolls out, so it is logged quietly rather
// than as an emit failure. Only 404s seen before this agent's first 2xx
// qualify — see errAccessEndpointGone. Matched via errors.Is because
// retry.Retry unwraps the PermanentError and returns this sentinel
// directly.
var errAccessEndpointNotDeployed = errors.New("access event endpoint not available (404)")

// errAccessEndpointGone marks a 404 seen after this agent has already had a
// 2xx from the endpoint. The endpoint clearly exists, so 404 no longer means
// "Phase 2 not deployed": alpacon-server answers 404 when the authenticated
// agent has no live Server row, i.e. the server was deleted in the console
// while its agent kept running. That is a reportable condition, not a quiet
// drop, so it is logged at Warn.
var errAccessEndpointGone = errors.New("access event endpoint returned 404 after a previous success (server row may have been deleted)")

// errAccessEventRejected marks a 4xx other than 404: the server refused this
// event (bad credentials, revoked permission, schema mismatch). Retrying
// cannot change the outcome, so the emit is abandoned immediately.
var errAccessEventRejected = errors.New("access event rejected")

// errAccessEventThrottled marks a 429. It is permanent rather than transient:
// alpacon-server's LocalAccessEventThrottle is a DRF SimpleRateThrottle, so
// its window is 60 seconds, while this client's whole retry budget is
// authRetryTimeout (25s). A window that outlives the budget cannot clear
// inside it, so every retry is guaranteed to re-throttle while pinning one of
// the emitConcurrencyLimit slots for the full budget. Saturating those slots
// starts dropping newly arriving events at the semaphore, which loses more
// audit records than dropping this one does.
var errAccessEventThrottled = errors.New("access event throttled (429)")

// Server-side max_length caps for the access event payload (alpacon-server
// events/models.py). DRF rejects an over-length string with a 400, which this
// client treats as permanent — so without truncation an over-long PAM item
// silently costs the whole audit record.
const (
	maxAccessEventUsernameLen = 128
	maxAccessEventServiceLen  = 64
	maxAccessEventRHostLen    = 255
	maxAccessEventTTYLen      = 64
)

// maxSessionAncestorDepth bounds the ppid walk used to attribute a session to
// an Alpacon-originated process tree. Three hops covers the deepest known
// case (su under sudo's use_pty monitor); the rest is headroom for wrappers.
const maxSessionAncestorDepth = 8

// SessionEventRequest is sent by alpamon-pam's pam_sm_open_session hook
// over auth.sock whenever a PAM session opens on a hooked service
// (sshd, login, su). rhost/tty are empty for sessions without them
// (e.g. local console logins have no rhost).
//
// PID/PPID are getpid()/getppid() of the process that opened the PAM
// session, not of the user's shell. For sshd that is the daemon child
// handling the connection, whose parent is the listening daemon; the
// login shell does not exist yet at pam_sm_open_session time. For su it
// is the su process itself.
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
	EventID  string `json:"event_id"`
	Username string `json:"username"`
	Service  string `json:"service"`
	RHost    string `json:"rhost,omitempty"`
	TTY      string `json:"tty,omitempty"`
	// PID/PPID are copied from SessionEventRequest and inherit its caveat:
	// they identify the process that opened the PAM session, which for sshd
	// is the daemon child, not the intruder's shell. An operator reading
	// these in the console should not expect a shell pid.
	PID       int       `json:"pid"`
	PPID      int       `json:"ppid"`
	Timestamp time.Time `json:"timestamp"`
}

// ancestorPIDs returns the chain of ancestors of pid, nearest first, stopping
// at init, at a broken link, or after maxSessionAncestorDepth hops. parentOf
// reports a pid's parent and whether it could be read at all. The returned
// chain never contains pid itself, and a pid that reports itself as its own
// parent terminates the walk rather than looping.
func ancestorPIDs(pid int, parentOf func(int) (int, bool)) []int {
	var chain []int
	current := pid
	for range maxSessionAncestorDepth {
		parent, ok := parentOf(current)
		if !ok || parent <= 1 || parent == current {
			break
		}
		chain = append(chain, parent)
		current = parent
	}
	return chain
}

// lookupSessionAncestorLocked resolves a session event to a tracked Alpacon
// session by walking the caller's ancestors. It exists because the direct
// (sid, ppid) pair is not always enough: sudo with use_pty on — the default on
// current Debian/Ubuntu — forks a monitor that calls setsid() and runs the
// command in a fresh session, so `sudo su -` inside a Websh terminal has
// neither a tracked sid nor a tracked parent. Its grandparent chain still
// leads back to the Websh PTY leader, which is what this walks. The caller
// must hold am.mu and must have collected chain outside the lock, since
// reading a process's parent is I/O.
func (am *AuthManager) lookupSessionAncestorLocked(chain []int) (*SessionInfo, bool) {
	for _, pid := range chain {
		if session, exists := am.pidToSessionMap[pid]; exists {
			return session, true
		}
	}
	return nil, false
}

// truncateRunes cuts s to at most limit UTF-8 codepoints and reports whether
// anything was dropped. Cutting on a codepoint boundary keeps the result valid
// UTF-8 instead of emitting a replacement character mid-sequence.
func truncateRunes(s string, limit int) (string, bool) {
	count := 0
	for index := range s {
		if count == limit {
			return s[:index], true
		}
		count++
	}
	return s, false
}

// resolveSessionEvent decides whether req represents a non-Alpacon
// session. It reuses the sudo-approval lookup: the caller's session id
// (shared by every process in a Websh or Command session) or its direct
// parent pid resolving to a tracker entry means the session originated
// from Alpacon — e.g. su executed inside a Websh terminal — and must be
// suppressed. When neither key matches, the caller's ancestor chain is
// walked as well, which is what catches `sudo su -` under sudo's use_pty.
// The second return value reports whether to emit.
//
// A process that deliberately detaches from its Alpacon parent still
// reports as non-Alpacon: setsid, nohup with a double fork, systemd-run
// and anything else reparented to init breaks both the session id and the
// ancestor chain. That is the safe direction (a false alarm, never a
// missed detection) and it is the documented limit of Phase 1 detection.
func (am *AuthManager) resolveSessionEvent(req SessionEventRequest) (NonAlpaconAccessEvent, bool) {
	sid, sidOK := sessionID(req.PID)
	am.mu.RLock()
	session, exists := am.lookupSessionLocked(sid, sidOK, req.PPID)
	am.mu.RUnlock()

	if !exists {
		// Only now walk the ancestor chain: it reads /proc, so it stays off the
		// path a direct hit already answers, and it must run outside am.mu
		// because no I/O may happen under that lock — the PAM producer is
		// blocked on our ack for the duration.
		chain := ancestorPIDs(req.PID, parentPID)
		am.mu.RLock()
		session, exists = am.lookupSessionAncestorLocked(chain)
		am.mu.RUnlock()
	}

	if exists {
		log.Debug().
			Str("kind", session.effectiveKind()).
			Str("session_id", session.SessionID).
			Str("command_id", session.CommandID).
			Int("pid", req.PID).
			Msg("Session event suppressed: Alpacon-originated session")
		return NonAlpaconAccessEvent{}, false
	}

	// Cap each string at the server's max_length. An over-length field would
	// come back as a 400, which this client treats as permanent, so the whole
	// audit record would be lost rather than just the excess characters.
	var truncated []string
	clamp := func(field, value string, limit int) string {
		out, cut := truncateRunes(value, limit)
		if cut {
			truncated = append(truncated, field)
		}
		return out
	}
	username := clamp("username", req.Username, maxAccessEventUsernameLen)
	service := clamp("service", req.Service, maxAccessEventServiceLen)
	rhost := clamp("rhost", req.RHost, maxAccessEventRHostLen)
	tty := clamp("tty", req.TTY, maxAccessEventTTYLen)
	if len(truncated) > 0 {
		log.Debug().
			Strs("fields", truncated).
			Int("pid", req.PID).
			Msg("Session event fields truncated to server limits")
	}

	return NonAlpaconAccessEvent{
		// Generated once here, so every retry of the same session
		// carries the same id.
		EventID:  uuid.NewString(),
		Username: username,
		Service:  service,
		RHost:    rhost,
		TTY:      tty,
		PID:      req.PID,
		// The server's ppid column is a PositiveIntegerField, so a negative
		// value from a malformed frame would 400 the whole event away.
		PPID:      max(req.PPID, 0),
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

	// Resolve (and its suppression Debug log) runs before the flag check on
	// purpose: it keeps the "why was this suppressed" trace available even
	// while detect_local_access is off, at the cost of one Getsid syscall and
	// a map lookup per session. The emit itself stays gated below.
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
		// Every slot busy means the server has been unreachable long enough
		// for retries to pile up while logins keep arriving — an abnormal
		// state that loses audit events, so surface it at Warn. Rate-limit the
		// Warn (at most once per minute) so a sustained outage can't flood the
		// log; intervening drops still record at Debug.
		//
		// Pick the level before allocating the event: a *zerolog.Event that is
		// never given a .Msg() is leaked out of the pool rather than reused.
		now := time.Now().Unix()
		warn := false
		if prev := lastEmitDropWarn.Load(); now-prev >= 60 &&
			lastEmitDropWarn.CompareAndSwap(prev, now) {
			warn = true
		}
		dropLog := log.Debug()
		if warn {
			dropLog = log.Warn()
		}
		dropLog.
			Str("username", event.Username).
			Str("service", event.Service).
			Msg("access event dropped: emit concurrency limit reached")
		return
	}
	go func() {
		// Registered first so it runs last: the slot is returned even if the
		// emit panics, otherwise one panic would permanently cost a slot.
		defer func() { <-am.emitSem }()
		defer func() {
			if r := recover(); r != nil {
				log.Error().Interface("panic", r).
					Str("username", event.Username).
					Str("service", event.Service).
					Msg("Access event emit panicked")
			}
		}()
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

	_ = conn.SetWriteDeadline(time.Now().Add(authSocketWriteTimeout))
	if _, err := conn.Write(responseJSON); err != nil {
		log.Warn().Err(err).Msg("Failed to send session_event_response")
	}
}

// emitAccessEvent POSTs a non-Alpacon access event to alpacon-server
// with bounded best-effort retry (same backoff envelope as the sudo
// approval path). It runs on its own goroutine; failures are logged and
// dropped so detection never blocks logins. Every 4xx is permanent: a 404
// before this agent's first 2xx means the endpoint is not deployed yet and
// drops quietly, a 404 after it means the server row is gone and is reported,
// and a 429 cannot clear inside the retry budget (see errAccessEventThrottled).
//
// Best-effort is literal: Stop() cancels the AuthManager context and closes
// the listener but does not wait for in-flight emits, and the HTTP layer does
// not observe am.ctx either, so up to emitConcurrencyLimit events can be lost
// on shutdown. Delivery here is not guaranteed and nothing downstream should
// assume it is.
func (am *AuthManager) emitAccessEvent(event NonAlpaconAccessEvent) {
	if am.session == nil {
		log.Warn().Msg("HTTP session not available; dropping access event")
		return
	}

	baseCtx := am.ctx
	if baseCtx == nil {
		baseCtx = context.Background()
	}
	// authRetryTimeout is reused only for its value here. Its "less than PAM's
	// 30s" rationale does not apply on this path: emit runs on its own
	// goroutine after the ack, so it never holds up PAM. The bound just caps
	// how long a single event keeps retrying an unreachable server.
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
			// Once the endpoint has answered 2xx on this agent, "not deployed"
			// stops being a plausible reading of 404 and the quiet drop would
			// hide the deleted-server case. Both readings are permanent; only
			// the log level differs.
			if am.accessEndpointSeen.Load() {
				return retry.Permanent(errAccessEndpointGone)
			}
			return retry.Permanent(errAccessEndpointNotDeployed)
		}
		// 429 is permanent here, not transient: see errAccessEventThrottled.
		if statusCode == http.StatusTooManyRequests {
			return retry.Permanent(errAccessEventThrottled)
		}
		// Any other 4xx means the server rejected this event (bad token,
		// revoked permission, schema mismatch); retrying cannot change the
		// verdict and would pin an emit slot for the whole backoff window,
		// dropping the events that arrive meanwhile. Fail fast instead.
		if statusCode >= 400 && statusCode < 500 {
			return retry.Permanent(fmt.Errorf(
				"%w with status code: %d", errAccessEventRejected, statusCode))
		}
		if statusCode < 200 || statusCode >= 300 {
			return fmt.Errorf("access event failed with status code: %d", statusCode)
		}
		// Latch the endpoint as deployed so a later 404 is read as the server
		// row being gone rather than as Phase 2 still being absent.
		am.accessEndpointSeen.Store(true)
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
		if errors.Is(err, errAccessEndpointGone) {
			log.Warn().Err(err).
				Str("username", event.Username).
				Str("service", event.Service).
				Msg("Access event endpoint returned 404; dropping event")
			return
		}
		if errors.Is(err, errAccessEventThrottled) {
			log.Warn().Err(err).
				Str("username", event.Username).
				Str("service", event.Service).
				Msg("Access event throttled by server; dropping event")
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
