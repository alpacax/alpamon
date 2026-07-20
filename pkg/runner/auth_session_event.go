package runner

import (
	"time"

	"github.com/rs/zerolog/log"
)

// nonAlpaconAccessEventURL is the alpacon-server ingestion endpoint for
// non-Alpacon access events. Phase 2 (server) must implement this path;
// until then alpamon treats 404 as "not deployed" and drops the event.
const nonAlpaconAccessEventURL = "/api/events/access/"

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
		Username:  req.Username,
		Service:   req.Service,
		RHost:     req.RHost,
		TTY:       req.TTY,
		PID:       req.PID,
		PPID:      req.PPID,
		Timestamp: time.Now().UTC(),
	}, true
}
