package runner

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
)

// nonAlpaconAccessEventURL is the Alpacon ingestion endpoint for non-Alpacon
// access events. The outbox holds an event on any 404 rather than dropping it.
const nonAlpaconAccessEventURL = "/api/events/access/"

// errNoHTTPSession is returned by postAccessEvent before the agent has an
// HTTP session; the outbox holds the event like any other failed send.
var errNoHTTPSession = errors.New("HTTP session not available")

// Server-side max_length caps for the access event payload. The server
// rejects an over-length string with a 400, which this client treats as
// permanent, so without truncation an over-long PAM item silently costs the
// whole audit record.
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
	// EventID makes delivery idempotent. The outbox resends on transport
	// errors and 5xx, which cannot distinguish "the server never got it"
	// from "the server stored it but the reply was lost"; without a stable
	// id per session, that second case records the same login twice. The
	// server treats (server, event_id) as unique, and the outbox keys its
	// rows on it.
	EventID  string `json:"event_id"`
	Username string `json:"username"`
	Service  string `json:"service"`
	RHost    string `json:"rhost,omitempty"`
	TTY      string `json:"tty,omitempty"`
	// PID/PPID are copied from SessionEventRequest and inherit its caveat:
	// they identify the process that opened the PAM session, which for sshd
	// is the daemon child, not the intruder's shell. An operator reading
	// these in the console should not expect a shell pid.
	PID  int `json:"pid"`
	PPID int `json:"ppid"`
	// Timestamp is when the host saw the session open. It is sent unchanged
	// however long the event was held.
	Timestamp time.Time `json:"timestamp"`
	// HeldSeconds is how long the outbox held the event before this send.
	// Omitted when zero, and set per send, never stored. Servers that predate
	// the field ignore it as an unknown key.
	HeldSeconds int64 `json:"held_seconds,omitempty"`
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
// hook. The ack is written first, then the event is stored in the outbox,
// whose drain goroutine delivers it, so PAM (and thus sshd) never waits on
// the server. Fail-open: every path answers the socket. Closing unixConn is
// the caller's job.
func (am *AuthManager) handleSessionEvent(data []byte, unixConn net.Conn) {
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
			Bool("has_username", req.Username != "").
			Str("service", req.Service).
			Int("pid", req.PID).
			Msg("Incomplete session_event request; dropping")
		am.sendSessionEventResponse(unixConn, false)
		return
	}

	// Resolve (and its suppression Debug log) runs before the flag check on
	// purpose: it keeps the "why was this suppressed" trace available even
	// while detect_local_access is off, at the cost of one Getsid syscall and
	// a map lookup per session. Storing the event stays gated below.
	event, emit := am.resolveSessionEvent(req)

	am.sendSessionEventResponse(unixConn, true)

	am.mu.RLock()
	detect := am.detectLocalAccess
	am.mu.RUnlock()

	// Turning detection off stops capture only. Events already held were
	// captured while the policy asked for them, so the outbox still delivers
	// them; the server accepts them regardless of the current setting.
	if !emit || !detect {
		return
	}
	if am.outbox == nil {
		log.Debug().Str("event_id", event.EventID).Msg("No access event store; dropping event")
		return
	}
	// A hook registered for both su and su-l, where su-l includes su, runs
	// twice for one `su -` and sends the same frame twice. Checked on the raw
	// request, before truncation, so two values cut to the same prefix never
	// collide.
	if am.sessionRepeats.isRepeat(req) {
		log.Debug().
			Str("username", req.Username).
			Int("pid", req.PID).
			Msg("Session event dropped: repeat from the same PAM transaction")
		return
	}
	// Closed before the hand-off so the login never waits on the outbox,
	// even for a PAM module that reads the ack until EOF; the caller's own
	// close afterwards is harmless. enqueue never blocks: the outbox's writer
	// stores the event.
	_ = unixConn.Close()
	am.outbox.enqueue(event)
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

// postAccessEvent sends one access event for the outbox. It reports the
// status and any Retry-After; deciding what to do with them is the outbox's.
func (am *AuthManager) postAccessEvent(ctx context.Context, event NonAlpaconAccessEvent) (int, time.Duration, error) {
	if am.session == nil {
		return 0, 0, errNoHTTPSession
	}
	_, status, header, err := am.session.PostWithContext(ctx, nonAlpaconAccessEventURL, event, accessOutboxPostTimeout)
	if err != nil {
		return 0, 0, err
	}
	return status, parseRetryAfter(header.Get("Retry-After"), time.Now()), nil
}
