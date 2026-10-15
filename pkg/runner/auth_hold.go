package runner

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"regexp"
	"strconv"
	"syscall"
	"time"

	"github.com/rs/zerolog/log"
)

// A sudo request the server holds for an approval decision.
//
// The server answers the post with an approval_pending body instead of a
// verdict. If the client said it can wait (hold_capable), alpamon writes one
// interim frame, keeps the connection open past the usual 30 s and relays the
// final verdict when it arrives on the control stream. The client protocol is
// newline-delimited JSON: interim frames, each ending in "\n", then exactly one
// final sudo_approval_response, then close. A client that did not send
// hold_capable reads everything to EOF as one JSON object, so it must never get
// an interim frame.

const (
	// Final codes alpamon itself answers a held or holdable request with.
	sudoCodeApprovalPending = "SUDO_APPROVAL_PENDING"
	sudoCodeAlreadyWaiting  = "SUDO_APPROVAL_ALREADY_WAITING"

	approvalPendingStatus = "approval_pending"
	approvalPendingFrame  = "sudo_approval_pending"

	// maxHoldWaitSeconds bounds the server's wait_seconds. The client gives up
	// at wait_seconds+60, capped at 660 s, so alpamon must stay below that.
	maxHoldWaitSeconds = 600
	// holdGrace is how long after the server's own deadline alpamon still waits
	// for the final verdict. It stays below the client's 60 s, so the client
	// hears alpamon's coded answer instead of timing out on its own.
	holdGrace = 45 * time.Second
	// endedHoldTTL is how long an ended wait's id stays guarded against a late
	// verdict: past the longest hold plus an identity check that may follow
	// an approval.
	endedHoldTTL = 15 * time.Minute
)

var (
	approvalRefPattern = regexp.MustCompile(`^[0-9a-fA-F-]{1,64}$`)
	holdReasonPattern  = regexp.MustCompile(`^[A-Z0-9_]{1,64}$`)
)

// approvalPending is the server's answer to the post when it holds the request.
type approvalPending struct {
	Status          string          `json:"status"`
	ApprovalRequest string          `json:"approval_request"`
	ExpiresAt       string          `json:"expires_at"`
	WaitSeconds     json.RawMessage `json:"wait_seconds"`
	HoldReason      string          `json:"hold_reason"`
	// Command is the form of the command the server will echo on the final
	// verdict, when it differs from what was sent. Optional.
	Command string `json:"command"`
}

// approvalPendingFrameBody is the interim frame written to the client.
type approvalPendingFrameBody struct {
	Type        string `json:"type"`
	RequestRef  string `json:"request_ref"`
	WaitSeconds int64  `json:"wait_seconds"`
	ExpiresAt   string `json:"expires_at"`
	HoldReason  string `json:"hold_reason,omitempty"`
}

// sudoHold is what alpamon knows about a held request.
type sudoHold struct {
	ref         string
	waitSeconds int64
	expiresAt   string
	holdReason  string
	// command, sessionID and commandID are what a verdict for this request
	// must carry. commandID is set only for a deploy Command request.
	command   string
	sessionID string
	commandID string
}

// endedHold remembers a wait that ended without a verdict.
type endedHold struct {
	command    string
	sessionID  string
	commandID  string
	rawCommand string
	runasUser  string
	until      time.Time
}

// sudoWaitEnded tells the server the client stopped waiting. The approval
// request stays open.
type sudoWaitEnded struct {
	RequestID string `json:"request_id"`
	Command   string `json:"command"`
	SessionID string `json:"session_id,omitempty"`
	CommandID string `json:"command_id,omitempty"`
}

// parseApprovalPending reports whether body is an approval_pending answer. A
// pending answer that is malformed still reports true with a nil hold: the
// server is holding, alpamon just cannot relay it.
func parseApprovalPending(body []byte) (*sudoHold, bool) {
	var status struct {
		Status string `json:"status"`
	}
	if len(body) == 0 || json.Unmarshal(body, &status) != nil || status.Status != approvalPendingStatus {
		return nil, false
	}

	var p approvalPending
	if err := json.Unmarshal(body, &p); err != nil {
		log.Warn().Err(err).Msg("Malformed approval_pending answer")
		return nil, true
	}
	// A JSON integer only: a quoted or fractional value is not a wait.
	wait, err := strconv.ParseInt(string(p.WaitSeconds), 10, 64)
	if err != nil || wait <= 0 || !approvalRefPattern.MatchString(p.ApprovalRequest) {
		log.Warn().Str("approval_request", p.ApprovalRequest).Str("wait_seconds", string(p.WaitSeconds)).
			Msg("approval_pending answer without a usable reference or wait")
		return nil, true
	}
	wait = min(wait, maxHoldWaitSeconds)

	expires, err := time.Parse(time.RFC3339, p.ExpiresAt)
	if err != nil {
		// Display only; the wait itself runs on wait_seconds.
		expires = time.Now().Add(time.Duration(wait) * time.Second)
	}

	hold := &sudoHold{
		ref:         p.ApprovalRequest,
		waitSeconds: wait,
		expiresAt:   expires.UTC().Format(time.RFC3339),
		command:     p.Command,
	}
	if holdReasonPattern.MatchString(p.HoldReason) {
		hold.holdReason = p.HoldReason
	}
	return hold, true
}

// interimFrame is the exact bytes of the interim frame for hold.
func interimFrame(hold *sudoHold) []byte {
	b, _ := json.Marshal(approvalPendingFrameBody{
		Type:        approvalPendingFrame,
		RequestRef:  hold.ref,
		WaitSeconds: hold.waitSeconds,
		ExpiresAt:   hold.expiresAt,
		HoldReason:  hold.holdReason,
	})
	return append(b, '\n')
}

// awaitHeldRequest runs the rest of a request the server answered with
// approval_pending. It is called by the waiter that registered sudoRequest, and
// every step below acts on that instance only: the request id is the sudo pid,
// which a newer request may reuse at any point of the wait.
func (am *AuthManager) awaitHeldRequest(sudoRequest *SudoRequest, hold *sudoHold) {
	req := sudoRequest.Request
	requestID := req.RequestID

	if hold != nil {
		if hold.command == "" {
			hold.command = req.Command
		}
		hold.sessionID = req.SessionID
		hold.commandID = req.CommandID
	}

	if !req.HoldCapable || hold == nil {
		// A client that did not offer to wait reads one object to EOF, so it
		// gets the final answer only: the request stays open on the server.
		log.Warn().Str("request_id", requestID).Bool("hold_capable", req.HoldCapable).
			Msg("Server holds a sudo request alpamon cannot relay; answering pending")
		if am.finalizeHeldRequest(sudoRequest, hold, "Approval pending", sudoCodeApprovalPending) {
			if hold != nil {
				go am.postWaitEnded(req, hold)
			}
		} else {
			am.endDisplacedHold(sudoRequest, hold)
			am.awaitTakenRequest(sudoRequest)
		}
		return
	}

	if !am.beginHold(sudoRequest, hold) {
		// Answered or displaced between the post and here; the taker signals
		// when done.
		am.endDisplacedHold(sudoRequest, hold)
		am.awaitTakenRequest(sudoRequest)
		return
	}

	peerGone := watchPeerClose(sudoRequest.Connection)
	written, err := writeInterimFrame(sudoRequest, hold)
	switch {
	case err != nil:
		log.WithLevel(authSocketWriteLevel(err)).Err(err).Str("request_id", requestID).
			Msg("Failed to send sudo_approval_pending")
		am.abandonHeldRequest(sudoRequest, hold, "interim frame not delivered")
		return
	case written:
		log.Info().Str("request_id", requestID).Str("approval_request", hold.ref).
			Int64("wait_seconds", hold.waitSeconds).Msg("sudo request waits for approval")
	}

	deadline := time.NewTimer(time.Duration(hold.waitSeconds)*time.Second + holdGrace)
	defer deadline.Stop()

	select {
	case <-sudoRequest.done:
		log.Debug().Str("request_id", requestID).Msg("Held sudo_approval request answered")
	case <-deadline.C:
		// The server's own deadline answer never arrived. The request stays open
		// for a re-run, which is what the code tells the client.
		if am.finalizeHeldRequest(sudoRequest, hold, "Approval pending", sudoCodeApprovalPending) {
			log.Warn().Str("request_id", requestID).Msg("Held sudo_approval request reached its deadline")
			go am.postWaitEnded(req, hold)
		} else {
			am.awaitTakenRequest(sudoRequest)
		}
	case <-peerGone:
		am.abandonHeldRequest(sudoRequest, hold, "client closed the connection")
	case <-am.ctx.Done():
		// The request stays open on the server, so a re-run after the restart
		// can pick it up. The ended-wait guard lives in memory and does not
		// survive the restart; the server's own deadline still ends the wait.
		if am.finalizeHeldRequest(sudoRequest, hold, "Service shutdown", sudoCodeApprovalPending) {
			am.postWaitEndedOnShutdown(req, hold)
		} else {
			am.awaitTakenRequest(sudoRequest)
		}
	}
}

// beginHold marks sudoRequest as held and reports whether it still was
// registered. It checks the instance, not the id, so a hold never attaches to a
// newer request that reuses the id.
func (am *AuthManager) beginHold(sudoRequest *SudoRequest, hold *sudoHold) bool {
	am.mu.Lock()
	defer am.mu.Unlock()
	if am.findRequestLocked(sudoRequest.Request.RequestID) != sudoRequest {
		return false
	}
	sudoRequest.hold = hold
	return true
}

// endDisplacedHold finishes a request that a newer one with the same id
// displaced while its post was in flight: the displacement found no hold to
// guard, so the pending answer that arrived since is guarded and reported now.
func (am *AuthManager) endDisplacedHold(sudoRequest *SudoRequest, hold *sudoHold) {
	if hold == nil {
		return
	}
	am.mu.Lock()
	displaced := sudoRequest.displaced
	report := displaced
	if displaced {
		am.rememberEndedHoldLocked(sudoRequest.Request, hold)
		// The newer request's post already went out and may have joined this
		// wait on the server, which keys it on the id and session. Ending it
		// then would end the newer request's wait too; the server's own
		// deadline ends it instead.
		if newer := am.findRequestLocked(sudoRequest.Request.RequestID); newer != nil &&
			newer.Request.SessionID == sudoRequest.Request.SessionID &&
			newer.Request.CommandID == sudoRequest.Request.CommandID {
			report = false
		}
	}
	am.mu.Unlock()
	if report {
		go am.postWaitEnded(sudoRequest.Request, hold)
	}
}

// writeInterimFrame writes the interim frame unless the final answer already
// went out. It reports whether it wrote.
func writeInterimFrame(req *SudoRequest, hold *sudoHold) (bool, error) {
	req.writeMu.Lock()
	defer req.writeMu.Unlock()
	if req.final {
		return false, nil
	}
	_ = req.Connection.SetWriteDeadline(time.Now().Add(authSocketWriteTimeout))
	if _, err := req.Connection.Write(interimFrame(hold)); err != nil {
		return false, err
	}
	return true, nil
}

// watchPeerClose reports the client closing its end. The client sends nothing
// after its request, so any read that ends in EOF or a reset means it is gone:
// Ctrl+C, a hang-up, or its own deadline. A read that fails because alpamon
// closed the connection itself reports nothing.
func watchPeerClose(conn net.Conn) <-chan struct{} {
	gone := make(chan struct{})
	go func() {
		buf := make([]byte, 64)
		for {
			_, err := conn.Read(buf)
			if err == nil {
				continue // Not part of the protocol; ignored.
			}
			if errors.Is(err, io.EOF) || errors.Is(err, syscall.ECONNRESET) {
				close(gone)
			}
			return
		}
	}()
	return gone
}

// abandonHeldRequest ends a held request whose client is gone: nothing is
// written, the connection is closed, and the server is told the wait ended.
func (am *AuthManager) abandonHeldRequest(sudoRequest *SudoRequest, hold *sudoHold, why string) {
	if !am.takeHeldLocked(sudoRequest, hold) {
		// A verdict is going out; it fails on the closed peer, which is fine.
		am.awaitTakenRequest(sudoRequest)
		return
	}

	sudoRequest.writeMu.Lock()
	sudoRequest.final = true
	_ = sudoRequest.Connection.Close()
	sudoRequest.writeMu.Unlock()
	am.signalCompletion(sudoRequest)

	req := sudoRequest.Request
	log.Info().Str("request_id", req.RequestID).Str("approval_request", hold.ref).Str("why", why).
		Msg("Stopped waiting for a sudo approval")
	go am.postWaitEnded(req, hold)
}

// finalizeHeldRequest denies sudoRequest with a code. It reports whether it
// took the request.
func (am *AuthManager) finalizeHeldRequest(sudoRequest *SudoRequest, hold *sudoHold, reason, errorCode string) bool {
	if !am.takeHeldLocked(sudoRequest, hold) {
		return false
	}
	am.denyPendingRequestsWithCode([]*SudoRequest{sudoRequest}, reason, errorCode)
	return true
}

// takeHeldLocked takes sudoRequest and, when hold is set, guards its id against
// the wait's late verdict in the same critical section, before anything is
// written: a newer request reusing the id can never register in between and
// take that verdict. It reports whether it took the request.
func (am *AuthManager) takeHeldLocked(sudoRequest *SudoRequest, hold *sudoHold) bool {
	am.mu.Lock()
	defer am.mu.Unlock()
	if !am.takeInstanceLocked(sudoRequest) {
		return false
	}
	if hold != nil {
		am.rememberEndedHoldLocked(sudoRequest.Request, hold)
	}
	return true
}

// waitEndedShutdownTimeout bounds a single wait-ended attempt: the one made
// while the agent stops, so it never holds up the shutdown, and the one made
// before a request that displaced a held one is forwarded.
const waitEndedShutdownTimeout = 3 * time.Second

func waitEndedURL(req SudoApprovalRequest, hold *sudoHold) string {
	return sudoApprovalURL(req) + hold.ref + "/wait-ended/"
}

func waitEndedBody(req SudoApprovalRequest) sudoWaitEnded {
	return sudoWaitEnded{
		RequestID: req.RequestID,
		Command:   req.Command,
		SessionID: req.SessionID,
		CommandID: req.CommandID,
	}
}

// postWaitEnded tells the server the client stopped waiting for hold. Best
// effort: the server's own deadline ends the wait if this never lands. It runs
// on its own goroutine, so the waiter returns (and frees the request id) at once.
func (am *AuthManager) postWaitEnded(req SudoApprovalRequest, hold *sudoHold) {
	if am.session == nil || am.ctx == nil {
		return
	}
	if err := am.postWithRetry(waitEndedURL(req, hold), waitEndedBody(req), nil); err != nil {
		log.Warn().Err(err).Str("request_id", req.RequestID).Str("approval_request", hold.ref).
			Msg("Failed to report the end of a sudo approval wait")
	}
}

// postWaitEndedOnShutdown makes one bounded attempt at the wait-ended post
// while the agent stops; am.ctx is already cancelled, so it cannot be used.
func (am *AuthManager) postWaitEndedOnShutdown(req SudoApprovalRequest, hold *sudoHold) {
	go am.postWaitEndedOnce(context.Background(), req, hold)
}

// postWaitEndedOnce makes one wait-ended attempt bounded by
// waitEndedShutdownTimeout and returns when it is done.
func (am *AuthManager) postWaitEndedOnce(parent context.Context, req SudoApprovalRequest, hold *sudoHold) {
	if am.session == nil {
		return
	}
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithTimeout(parent, waitEndedShutdownTimeout)
	defer cancel()
	_, status, _, err := am.session.PostWithContext(ctx, waitEndedURL(req, hold), waitEndedBody(req), waitEndedShutdownTimeout/time.Second)
	if err != nil || status < 200 || status >= 300 {
		log.Warn().Err(err).Int("status_code", status).Str("request_id", req.RequestID).
			Msg("Could not report the end of a sudo approval wait")
	}
}

// liveHoldForLocked reports whether the same session (or deploy Command)
// already holds a request for the same command and run-as user: one wait per
// session. Waits across sessions are the server's to deduplicate, since two
// Alpacon users may share one host account. Callers must hold am.mu.
func (am *AuthManager) liveHoldForLocked(req SudoApprovalRequest) bool {
	for _, session := range am.pidToSessionMap {
		for _, other := range session.Requests {
			if other.hold != nil &&
				other.Request.SessionID == req.SessionID &&
				other.Request.CommandID == req.CommandID &&
				other.Request.Username == req.Username &&
				other.Request.RunasUser == req.RunasUser &&
				other.Request.Command == req.Command {
				return true
			}
		}
	}
	return false
}

// findRequestLocked returns the registered request for id without taking it.
// Callers must hold am.mu.
func (am *AuthManager) findRequestLocked(requestID string) *SudoRequest {
	for _, session := range am.pidToSessionMap {
		if req, exists := session.Requests[requestID]; exists {
			return req
		}
	}
	return nil
}

// mismatchLocked says why response must not be applied to req, the request
// registered under its id (nil when none), or "" when it may. Every verdict
// must name the request's session (empty for a deploy Command), and a command
// id when it names one: the id alone is the sudo pid, which another session may
// reuse. A held request also takes only a verdict that names its command and,
// for a deploy Command, its command id. A verdict that names a wait which
// already ended is not applied to a different request that reuses the id, held
// or not. Callers must hold am.mu.
func (am *AuthManager) mismatchLocked(response SudoApprovalResponse, req *SudoRequest) string {
	if req != nil {
		switch {
		case response.SessionID != req.Request.SessionID:
			return "session"
		case response.CommandID != "" && response.CommandID != req.Request.CommandID:
			return "command id"
		}
	}
	if req != nil && req.hold != nil {
		switch {
		case response.Command != req.hold.command:
			return "command"
		case response.CommandID != req.hold.commandID:
			return "command id"
		}
	}

	ended, ok := am.endedHolds[response.RequestID]
	if !ok {
		return ""
	}
	if time.Now().After(ended.until) {
		delete(am.endedHolds, response.RequestID)
		return ""
	}
	if response.Command != ended.command || response.SessionID != ended.sessionID ||
		response.CommandID != ended.commandID {
		return "" // Not the ended wait's verdict.
	}
	if req != nil && req.Request.Command == ended.rawCommand &&
		req.Request.SessionID == ended.sessionID && req.Request.CommandID == ended.commandID &&
		req.Request.RunasUser == ended.runasUser {
		return "" // The same command, session and run-as user: the verdict fits it too.
	}
	return "ended wait"
}

// rememberEndedHoldLocked guards the id of a wait that ended without a verdict.
// Callers must hold am.mu.
func (am *AuthManager) rememberEndedHoldLocked(req SudoApprovalRequest, hold *sudoHold) {
	now := time.Now()
	if am.endedHolds == nil {
		am.endedHolds = make(map[string]endedHold)
	}
	for id, ended := range am.endedHolds {
		if now.After(ended.until) {
			delete(am.endedHolds, id)
		}
	}
	am.endedHolds[req.RequestID] = endedHold{
		command:    hold.command,
		sessionID:  hold.sessionID,
		commandID:  hold.commandID,
		rawCommand: req.Command,
		runasUser:  req.RunasUser,
		until:      now.Add(endedHoldTTL),
	}
}
