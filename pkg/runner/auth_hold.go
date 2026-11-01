package runner

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/rs/zerolog/log"
)

// storedCommandMarker is the separator the server puts before the digest in
// its stored command form. Any command containing it is treated as possibly
// in that form, so a change to the digest's length or alphabet keeps matching.
const storedCommandMarker = " #k:"

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
	// endedHoldTTL covers the server's 24-hour pending approval lifetime,
	// its five-minute expiry sweep, and five minutes for verdict delivery.
	endedHoldTTL       = 24*time.Hour + 10*time.Minute
	maxEndedHoldsPerID = 64
	maxEndedHolds      = 65536
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

// endedHold retains the identity and individual expiry of a request that ended
// with or without a verdict. The window assumes the server stops accepting a
// grant's verdict well within it. Each record is fixed-size: 192 bytes on 64-bit
// targets, at most 12 MiB for 65536 records, excluding map, slice and expiry
// queue overhead. Saturation starts at 65536 records per 24h10m, about 0.75
// endings per second sustained. Records are capped at 64 per id. Saturation
// keeps at most one small marker per id; ids are decimal PIDs, bounded by the
// PID space. The expiry queue holds at most max(64, twice the live record
// and marker count) entries, compacting stale refreshes when it exceeds that bound.
type endedHold struct {
	command    [sha256.Size]byte
	sessionID  [sha256.Size]byte
	commandID  [sha256.Size]byte
	identity   [sha256.Size]byte
	rawCommand [sha256.Size]byte
	until      time.Time
	// unheld marks an ending whose server-form command is unknown.
	unheld bool
}

// endedExpiry identifies a detailed record or an id-wide saturation marker.
// A zero record is used only for markers; marker distinguishes the two kinds.
type endedExpiry struct {
	id     string
	record endedHold
	until  time.Time
	marker bool
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
	prepareHold(hold, req)

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

// prepareHold fills in what a verdict for hold must carry. Idempotent; a nil
// hold is a no-op.
func prepareHold(hold *sudoHold, req SudoApprovalRequest) {
	if hold == nil {
		return
	}
	if hold.command == "" {
		hold.command = req.Command
	}
	hold.sessionID = req.SessionID
	hold.commandID = req.CommandID
}

// bindPostAnswer keeps an attempt bound once any POST answer echoes its nonce.
func (am *AuthManager) bindPostAnswer(sudoRequest *SudoRequest, body []byte) {
	var answer struct {
		ApprovalNonce json.RawMessage `json:"approval_nonce"`
	}
	bound := false
	// Error pages from a proxy are not JSON objects and carry no acknowledgement.
	if trimmed := bytes.TrimSpace(body); len(trimmed) > 0 && trimmed[0] == '{' {
		if err := json.Unmarshal(body, &answer); err != nil {
			log.Debug().Str("request_id", sudoRequest.Request.RequestID).Msg("Malformed sudo approval POST acknowledgement")
		} else if len(answer.ApprovalNonce) > 0 {
			var nonce string
			if err := json.Unmarshal(answer.ApprovalNonce, &nonce); err == nil && nonce != "" &&
				subtle.ConstantTimeCompare([]byte(nonce), []byte(sudoRequest.Request.ApprovalNonce)) == 1 {
				bound = true
			} else {
				log.Debug().Str("request_id", sudoRequest.Request.RequestID).Msg("Sudo approval POST acknowledgement nonce does not match")
			}
		}
	}
	if bound {
		am.mu.Lock()
		sudoRequest.nonceBound = true
		am.mu.Unlock()
	}
}

// settlePost ends sudoRequest's posting state once the post is classified:
// hold is the server's pending answer, or nil when it did not hold the request.
// Parked verdicts are checked after applying the acknowledgement binding.
// Unbound nonce-less verdicts use retention and the hold command. The first
// that fits is taken with the request and returned; the rest are dropped. A hold is
// attached in the same critical section, so no verdict slips in unchecked.
func (am *AuthManager) settlePost(sudoRequest *SudoRequest, hold *sudoHold, body []byte) (SudoApprovalResponse, bool) {
	am.bindPostAnswer(sudoRequest, body)
	am.mu.Lock()
	defer am.mu.Unlock()
	sudoRequest.posting = false
	early := sudoRequest.early
	sudoRequest.early = nil
	if am.findRequestLocked(sudoRequest.Request.RequestID) != sudoRequest {
		return SudoApprovalResponse{}, false
	}
	if hold != nil {
		sudoRequest.hold = hold
	}
	for _, verdict := range early {
		if reason := am.verdictMismatchLocked(verdict, sudoRequest); reason != "" {
			log.WithLevel(sudoVerdictDropLevel(reason)).Str("request_id", verdict.RequestID).Str("mismatch", reason).
				Msg("Dropped a sudo_approval response that arrived before the post was answered")
			continue
		}
		am.takeInstanceLocked(sudoRequest)
		am.rememberEndedLocked(sudoRequest)
		return verdict, true
	}
	return SudoApprovalResponse{}, false
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
		am.rememberEndedLocked(&SudoRequest{Request: sudoRequest.Request, hold: hold})
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

// takeHeldLocked takes sudoRequest and guards its id against a late verdict
// in the same critical section, before anything is written: a newer request
// reusing the id can never register in between and take that verdict. It
// reports whether it took the request.
func (am *AuthManager) takeHeldLocked(sudoRequest *SudoRequest, hold *sudoHold) bool {
	am.mu.Lock()
	defer am.mu.Unlock()
	if !am.takeInstanceLocked(sudoRequest) {
		return false
	}
	am.rememberEndedLocked(&SudoRequest{Request: sudoRequest.Request, hold: hold})
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
	_, status, _, err := am.session.PostWithContext(parent, waitEndedURL(req, hold), waitEndedBody(req), waitEndedShutdownTimeout)
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

// mismatchLocked checks session and held-command routing, then every live ending
// for this id in the verdict's session. Held endings compare their known server
// command and full identity. Unheld endings require the same identity, or a
// verdict naming the current raw command and a different ended raw command.
// Records in other sessions do not constrain matching. A saturated id refuses
// every verdict until its unstored endings expire. Callers must hold am.mu.
// A refused verdict leaves the request waiting until its own timeout.
func (am *AuthManager) mismatchLocked(response SudoApprovalResponse, req *SudoRequest) string {
	am.pruneEndedLocked(time.Now())
	if _, saturated := am.saturatedEndedIDs[response.RequestID]; saturated {
		return "ended records saturated"
	}
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

	responseCommand := sha256.Sum256([]byte(response.Command))
	responseSession := sha256.Sum256([]byte(response.SessionID))
	responseCommandID := sha256.Sum256([]byte(response.CommandID))
	for _, ended := range am.endedHolds[response.RequestID] {
		if req != nil && ended.sameIdentity(req.Request) {
			continue
		}
		if responseSession != ended.sessionID {
			continue
		}
		if response.CommandID != "" && responseCommandID != ended.commandID {
			continue
		}
		command := ""
		if req != nil {
			command = req.Request.Command
			if req.hold != nil {
				command = req.hold.command
			}
		}
		if response.Command == "" || response.Command != command {
			return "ended request"
		}
		if ended.unheld {
			if !(response.Command == req.Request.Command && ended.rawCommand != responseCommand &&
				!strings.Contains(req.Request.Command, storedCommandMarker)) {
				return "ended request"
			}
		} else if responseCommand == ended.command {
			return "ended wait"
		}
	}
	return ""
}

func (ended endedHold) sameIdentity(req SudoApprovalRequest) bool {
	return ended.identity == sudoIdentityHash(req)
}

func sudoIdentityHash(req SudoApprovalRequest) [sha256.Size]byte {
	h := sha256.New()
	for _, field := range []string{req.SessionID, req.CommandID, req.Command, req.RunasUser, req.Username, req.Groupname, strconv.FormatBool(req.IsAlpconUser)} {
		var size [8]byte
		binary.BigEndian.PutUint64(size[:], uint64(len(field)))
		h.Write(size[:])
		io.WriteString(h, field)
	}
	var digest [sha256.Size]byte
	copy(digest[:], h.Sum(nil))
	return digest
}

// rememberEndedLocked records a request's ending with or without a hold.
// Callers must hold am.mu.
func (am *AuthManager) rememberEndedLocked(req *SudoRequest) {
	r := req.Request
	ended := endedHold{
		rawCommand: sha256.Sum256([]byte(r.Command)),
		unheld:     req.hold == nil,
	}
	if req.hold != nil {
		ended.command = sha256.Sum256([]byte(req.hold.command))
		r.SessionID = req.hold.sessionID
		r.CommandID = req.hold.commandID
	}
	ended.sessionID = sha256.Sum256([]byte(r.SessionID))
	ended.commandID = sha256.Sum256([]byte(r.CommandID))
	ended.identity = sudoIdentityHash(r)
	am.rememberLocked(r.RequestID, ended)
}

// rememberLocked refreshes identical records and retains distinct live endings.
// At either detail limit, an id-wide refusal covers each unstored ending's expiry.
// Endings that fit do not extend that refusal. Callers must hold am.mu.
func (am *AuthManager) rememberLocked(requestID string, ended endedHold) {
	now := time.Now()
	am.pruneEndedLocked(now)
	defer am.compactEndedQueueLocked()
	ended.until = now.Add(endedHoldTTL)
	for i, record := range am.endedHolds[requestID] {
		record.until = ended.until
		if record == ended {
			am.endedHolds[requestID][i] = ended
			am.endedExpiryQueue = append(am.endedExpiryQueue, endedExpiry{id: requestID, record: ended, until: ended.until})
			return
		}
	}
	_, saturated := am.saturatedEndedIDs[requestID]
	limit := am.endedHoldLimit
	if limit == 0 {
		limit = maxEndedHolds
	}
	if len(am.endedHolds[requestID]) >= maxEndedHoldsPerID || am.endedCount >= limit {
		if am.saturatedEndedIDs == nil {
			am.saturatedEndedIDs = make(map[string]time.Time)
		}
		am.saturatedEndedIDs[requestID] = ended.until
		am.endedExpiryQueue = append(am.endedExpiryQueue, endedExpiry{id: requestID, until: ended.until, marker: true})
		if !saturated {
			log.Warn().Str("request_id", requestID).Msg("Ended sudo request records saturated")
		}
		return
	}
	if am.endedHolds == nil {
		am.endedHolds = make(map[string][]endedHold)
	}
	am.endedHolds[requestID] = append(am.endedHolds[requestID], ended)
	am.endedCount++
	am.endedExpiryQueue = append(am.endedExpiryQueue, endedExpiry{id: requestID, record: ended, until: ended.until})
}

// pruneEndedLocked removes expired records and refusals, returning the number
// of queue entries visited. Callers must hold am.mu.
func (am *AuthManager) pruneEndedLocked(now time.Time) int {
	visits := 0
	for len(am.endedExpiryQueue) > 0 {
		entry := am.endedExpiryQueue[0]
		visits++
		if now.Before(entry.until) {
			break
		}
		am.endedExpiryQueue[0] = endedExpiry{}
		am.endedExpiryQueue = am.endedExpiryQueue[1:]
		if entry.marker {
			if am.saturatedEndedIDs[entry.id] == entry.until {
				delete(am.saturatedEndedIDs, entry.id)
			}
			continue
		}
		records := am.endedHolds[entry.id]
		for i, record := range records {
			if record != entry.record {
				continue
			}
			records = append(records[:i], records[i+1:]...)
			clear(records[len(records) : len(records)+1])
			am.endedCount--
			if len(records) == 0 {
				delete(am.endedHolds, entry.id)
			} else {
				am.endedHolds[entry.id] = records
			}
			break
		}
	}
	if len(am.endedExpiryQueue) == 0 {
		am.endedExpiryQueue = nil
	}
	am.compactEndedQueueLocked()
	return visits
}

// compactEndedQueueLocked discards stale entries once they outnumber live ones.
func (am *AuthManager) compactEndedQueueLocked() {
	live := am.endedCount + len(am.saturatedEndedIDs)
	if len(am.endedExpiryQueue) <= 64 || len(am.endedExpiryQueue) <= 2*live {
		return
	}
	current := make(map[endedExpiry]struct{}, live)
	for id, records := range am.endedHolds {
		for _, record := range records {
			current[endedExpiry{id: id, record: record, until: record.until}] = struct{}{}
		}
	}
	for id, until := range am.saturatedEndedIDs {
		current[endedExpiry{id: id, until: until, marker: true}] = struct{}{}
	}
	// Filtering the already ordered queue keeps expiry order in linear time.
	queue := make([]endedExpiry, 0, live)
	for _, entry := range am.endedExpiryQueue {
		if _, ok := current[entry]; ok {
			queue = append(queue, entry)
			delete(current, entry)
		}
	}
	am.endedExpiryQueue = queue
}
