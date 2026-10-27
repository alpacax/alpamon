package runner

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"syscall"
	"time"

	"github.com/alpacax/alpamon/v2/internal/retry"
	"github.com/alpacax/alpamon/v2/pkg/db/ent"
	"github.com/alpacax/alpamon/v2/pkg/scheduler"
	"github.com/alpacax/alpamon/v2/pkg/utils"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// Kinds of tracked processes that may issue sudo through alpamon-pam.
const (
	// TrackerKindWebsh marks an interactive Websh PTY session.
	TrackerKindWebsh = "websh"
	// TrackerKindCommand marks a non-interactive deploy shell Command execution.
	TrackerKindCommand = "command"
)

// SessionInfo tracks a process (Websh PTY or deploy shell Command) that
// alpamon-pam may later encounter by walking the ppid chain. The same map
// holds both kinds of entries so the PAM lookup logic stays single-path.
//
// Exactly one of SessionID or CommandID is populated, determined by Kind:
//   - Kind == TrackerKindWebsh:   SessionID set, CommandID empty.
//   - Kind == TrackerKindCommand: CommandID set, SessionID empty.
//
// Legacy entries created before the Kind field was introduced are treated
// as websh entries for backward compatibility (see effectiveKind).
type SessionInfo struct {
	Kind      string
	SessionID string
	CommandID string
	Username  string
	PID       int
	StartedAt time.Time
	PtyClient *PtyClient
	Requests  map[string]*SudoRequest
}

// effectiveKind returns the Kind of an entry, defaulting to websh when
// the field is empty (older in-memory entries predating the Kind field).
func (s *SessionInfo) effectiveKind() string {
	if s == nil || s.Kind == "" {
		return TrackerKindWebsh
	}
	return s.Kind
}

type SudoRequest struct {
	Connection net.Conn
	// Request is kept whole so whoever finalizes it can answer with the fields
	// the PAM client sent.
	Request SudoApprovalRequest

	// writeMu serializes writes to Connection: the waiter's interim frame and
	// the taker's final response may race. final, guarded by writeMu, marks
	// that the final response went out (or the connection was given up), after
	// which nothing more may be written.
	writeMu sync.Mutex
	final   bool
	// hold is set under am.mu once the server answered that the request waits
	// for an approval decision. Nil for every other request.
	hold *sudoHold

	// done is this request's own completion channel: whoever takes the request
	// signals it once it is done with the connection. It belongs to the instance,
	// not to the request id, because the id is the sudo pid, which the kernel
	// reuses: a signal or cleanup looked up by id could reach a newer request.
	// Capacity 1 is load-bearing: signalCompletion sends without blocking, so an
	// unbuffered channel drops a signal that beats the waiter's select.
	done chan struct{}
	// displaced, guarded by am.mu, marks a request a newer one with the same id
	// pushed out of the registry. Its sudo process is gone (the kernel reused
	// its pid), so nothing is written to it.
	displaced bool
	// posting, guarded by am.mu, marks a request whose post has not been
	// answered yet: whether the server holds it is still unknown, so a verdict
	// that arrives now is parked in early until settlePost classifies the post.
	posting bool
	early   []SudoApprovalResponse
}

// maxEarlyVerdicts bounds the verdicts parked on one request while its post is
// in flight.
const maxEarlyVerdicts = 4

// newSudoRequest is the one way to build a registered request, so every
// instance carries its own completion channel.
func newSudoRequest(conn net.Conn, req SudoApprovalRequest) *SudoRequest {
	return &SudoRequest{Connection: conn, Request: req, done: make(chan struct{}, 1)}
}

type SudoApprovalRequest struct {
	RequestID    string `json:"request_id"`
	Type         string `json:"type"`
	Username     string `json:"username"`
	Groupname    string `json:"groupname"`
	PID          int    `json:"pid"`
	PPID         int    `json:"ppid"`
	Command      string `json:"command"`
	IsAlpconUser bool   `json:"is_alpacon_user"`
	SessionID    string `json:"session_id,omitempty"`
	CommandID    string `json:"command_id,omitempty"`
	// RunasUser is the OS user sudo will run the command as, as the approval
	// plugin reports it (a user name, or "#<uid>"). Forwarded unchanged to the
	// server; omitted when the client does not send it.
	RunasUser string `json:"runas_user,omitempty"`
	// HoldCapable reports that the client can show a pending approval and keep
	// waiting for the decision. Forwarded unchanged to the server; only a request
	// that carried it may receive an interim frame.
	HoldCapable bool `json:"hold_capable,omitempty"`
}

type SudoApprovalResponse struct {
	RequestID       string `json:"request_id"`
	Type            string `json:"type"`
	Username        string `json:"username"`
	Groupname       string `json:"groupname"`
	PID             int    `json:"pid"`
	PPID            int    `json:"ppid"`
	Command         string `json:"command"`
	IsAlpconUser    bool   `json:"is_alpacon_user"`
	SessionID       string `json:"session_id,omitempty"`
	CommandID       string `json:"command_id,omitempty"`
	Approved        bool   `json:"approved"`
	Reason          string `json:"reason"`
	Hint            string `json:"hint,omitempty"`
	ApprovalRequest string `json:"approval_request,omitempty"`
	// ErrorCode is an optional machine-readable denial code (e.g.
	// SUDO_NO_WORKSESSION_POLICY) from alpacon-server. Its value is forwarded
	// unchanged to the auth socket so the PAM module / approval plugin can show
	// a specific reason. omitempty omits the key when the server doesn't send
	// it, keeping older socket clients unaffected.
	ErrorCode string `json:"error_code,omitempty"`
}

type MFAResponse struct {
	RequestID    string `json:"request_id"`
	SessionID    string `json:"session_id"`
	Username     string `json:"username"`
	Groupname    string `json:"groupname"`
	PID          int    `json:"pid"`
	PPID         int    `json:"ppid"`
	IsAlpconUser bool   `json:"is_alpacon_user"`
	Success      bool   `json:"success"`
}

type BaseRequest struct {
	Type string `json:"type"`
	PID  int    `json:"pid"`
}

type IsAlpconRequest struct {
	Type      string `json:"type"`
	Username  string `json:"username"`
	Groupname string `json:"groupname"`
	PID       int    `json:"pid"`
	PPID      int    `json:"ppid"`
}

type IsAlpconResponse struct {
	Type         string `json:"type"`
	Username     string `json:"username"`
	Groupname    string `json:"groupname"`
	PID          int    `json:"pid"`
	PPID         int    `json:"ppid"`
	IsAlpconUser bool   `json:"is_alpacon_user"`
}

type AuthManager struct {
	mu              sync.RWMutex
	ctx             context.Context
	cancel          context.CancelFunc
	pidToSessionMap map[int]*SessionInfo
	controlClient   *ControlClient
	listener        net.Listener
	// peerCreds reads the kernel's view of an auth.sock peer; nil drops every connection.
	peerCreds         func(net.Conn) (peerCred, error)
	session           *scheduler.Session
	blockLocalSudo    bool
	detectLocalAccess bool
	// outbox holds non-Alpacon access events until the server has them. Set
	// once by UseAccessEventStore before Start; nil means events are dropped.
	outbox *accessEventOutbox
	// sessionRepeats drops a session event the PAM stack sent twice for one
	// login. It has its own lock, so intake never takes mu for it.
	sessionRepeats sessionEventRepeats
	// endedHolds remembers waits that ended without a server verdict, so a late
	// verdict for one is not applied to a new request that reuses its id.
	// Guarded by mu; created on first use.
	endedHolds map[string]endedHold
}

const (
	authRetryInitialInterval = 1 * time.Second
	authRetryMaxInterval     = 10 * time.Second
	authRetryTimeout         = 25 * time.Second // Less than PAM 30s timeout
	// authSocketWriteTimeout bounds every write to auth.sock. Session teardown and
	// Command registration deny leftover requests inline, so a peer that stopped
	// reading must not stall them.
	authSocketWriteTimeout = 5 * time.Second
	// authSocketHandoverTimeout outlives one bounded write, which is all a taker
	// needs before it signals. A longer silence means the signal is never coming.
	authSocketHandoverTimeout = authSocketWriteTimeout + time.Second
	// authSocketReadBufferSize bounds a single auth.sock request. The largest
	// frame is a session_event carrying all four PAM items at alpamon-pam's
	// PAM_ITEM_MAX_LEN of 256 bytes: ~1.1 KB of plain ASCII, but jansson
	// escapes control bytes 6:1, so the encoded form can reach ~6.5 KB. The
	// previous 1 KB truncated those into a JSON parse error, which closed the
	// connection and lost the audit event.
	authSocketReadBufferSize = 8192
	// sudoApprovalResponseTimeout is how long a request the server did not hold
	// waits for its verdict after the post.
	sudoApprovalResponseTimeout = 30 * time.Second
)

var (
	authManager     *AuthManager
	authManagerOnce sync.Once
)

func GetAuthManager(controlClient *ControlClient, session *scheduler.Session) *AuthManager {
	authManagerOnce.Do(func() {
		authManager = &AuthManager{
			pidToSessionMap: make(map[int]*SessionInfo),
			session:         session,
			peerCreds:       peerCredentials,
		}
	})

	if authManager.controlClient == nil {
		authManager.controlClient = controlClient
	}

	if authManager.session == nil {
		authManager.session = session
	}

	return authManager
}

func (am *AuthManager) UpdateBlockLocalSudo(value bool) {
	am.mu.Lock()
	defer am.mu.Unlock()
	if am.blockLocalSudo == value {
		return
	}
	am.blockLocalSudo = value
	log.Info().Bool("block_local_sudo", value).Msg("Updated block_local_sudo setting")
}

func (am *AuthManager) UpdateDetectLocalAccess(value bool) {
	am.mu.Lock()
	defer am.mu.Unlock()
	if am.detectLocalAccess == value {
		return
	}
	am.detectLocalAccess = value
	log.Info().Bool("detect_local_access", value).Msg("Updated detect_local_access setting")
}

// UseAccessEventStore gives the manager the agent's database to hold access
// events in until the server has them. Call it once, before Start.
func (am *AuthManager) UseAccessEventStore(client *ent.Client) {
	if client == nil {
		return
	}
	am.outbox = newAccessEventOutbox(client, am.postAccessEvent)
}

// NotifyServerReachable tells the access event outbox that the server answered
// again, so events held through an outage go out without waiting out the
// backoff. Safe to call from any goroutine, and before Start.
func (am *AuthManager) NotifyServerReachable() {
	if am.outbox != nil {
		am.outbox.notifyReachable()
	}
}

func (am *AuthManager) Start(ctx context.Context) {
	am.ctx, am.cancel = context.WithCancel(ctx)

	// Started ahead of the listener, so events held from a previous run are
	// delivered even if the socket cannot be opened.
	if am.outbox != nil {
		am.outbox.start(am.ctx)
	}

	if err := am.startSocketListener(am.ctx); err != nil {
		log.Error().Err(err).Msg("Failed to start socket listener")
		return
	}

	log.Info().Msg("Auth Manager started successfully")

	<-am.ctx.Done()
	log.Info().Msg("Auth Manager stopped")
}

func (am *AuthManager) startSocketListener(ctx context.Context) error {
	socketPath := filepath.Join(utils.RunDir(), "auth.sock")
	socketDir := filepath.Dir(socketPath)

	// Ensure socket directory exists as a fallback when systemd-tmpfiles
	// has not run yet (e.g., service restart after package upgrade without reboot).
	if err := os.MkdirAll(socketDir, 0750); err != nil {
		return fmt.Errorf("failed to create socket directory %q: %w", socketDir, err)
	}

	listener, err := listenAuthSocket(socketPath)
	if err != nil {
		return fmt.Errorf("socket listen error: %w", err)
	}

	log.Info().Msgf("Auth socket created at %s", socketPath)

	am.listener = listener
	log.Info().Msg("Auth socket listener started")

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
			unixConn, err := am.listener.Accept()
			if err != nil {
				if ctx.Err() != nil {
					return nil
				}
				log.Warn().Err(err).Msg("Socket accept error")
				continue
			}

			go am.handleSudoRequest(unixConn)
		}
	}
}

// sendSudoRequestWithRetry posts the request and returns the body of the
// successful answer, which says whether the server holds the request.
func (am *AuthManager) sendSudoRequestWithRetry(req SudoApprovalRequest) ([]byte, error) {
	var body []byte
	err := am.postWithRetry(sudoApprovalURL(req), req, &body)
	return body, err
}

// postWithRetry posts payload to url until a 2xx answer or authRetryTimeout,
// storing the answer's body in *body when body is not nil.
func (am *AuthManager) postWithRetry(url string, payload any, body *[]byte) error {
	b := &retry.ExponentialBackoff{
		InitialInterval: authRetryInitialInterval,
		MaxInterval:     authRetryMaxInterval,
		MaxElapsedTime:  authRetryTimeout,
	}

	ctx, cancel := context.WithTimeout(am.ctx, authRetryTimeout)
	defer cancel()

	return retry.Retry(ctx, b, am.createSendOperation(ctx, url, payload, body))
}

// sudoApprovalURL is the endpoint a sudo request is posted to. Deploy shell
// (Command) sudo requests go to the session-less endpoint so the server can
// resolve the IAM user via command_id.
func sudoApprovalURL(req SudoApprovalRequest) string {
	if req.CommandID != "" && req.SessionID == "" {
		return "/api/sudo/approval/"
	}
	return fmt.Sprintf("/api/websh/sessions/%s/sudo-approval/", req.SessionID)
}

func (am *AuthManager) createSendOperation(ctx context.Context, url string, payload any, body *[]byte) func() error {
	return func() error {
		select {
		case <-ctx.Done():
			return retry.Permanent(ctx.Err())
		default:
			if am.session == nil {
				return fmt.Errorf("HTTP session not available")
			}

			resp, statusCode, err := am.session.Post(url, payload, scheduler.DefaultRequestTimeout)
			if err != nil {
				log.Warn().Err(err).Str("url", url).Msg("Failed to send sudo request via REST API, will retry")
				return err
			}

			if statusCode < 200 || statusCode >= 300 {
				log.Warn().Int("status_code", statusCode).Str("url", url).Msgf("Sudo request failed with status %d, will retry", statusCode)
				return fmt.Errorf("sudo request failed with status code: %d", statusCode)
			}

			if body != nil {
				*body = resp
			}
			log.Debug().Str("url", url).Msg("Sudo request sent successfully via REST API")
			return nil
		}
	}
}

// lookupSessionLocked resolves a sudo request to its tracked session. It prefers
// the caller's session ID (sid)—shared by every process in the Websh or command
// session, so it survives the shell exec'ing sudo and any intermediate
// processes between the shell and sudo—and falls back to the direct parent-pid
// lookup for sessions whose registered leader is the caller's parent. The caller
// must hold am.mu (read or write).
func (am *AuthManager) lookupSessionLocked(sid int, sidOK bool, parentPID int) (*SessionInfo, bool) {
	if sidOK {
		if session, exists := am.pidToSessionMap[sid]; exists {
			return session, true
		}
	}
	session, exists := am.pidToSessionMap[parentPID]
	return session, exists
}

func (am *AuthManager) handleSudoRequest(unixConn net.Conn) {
	// Panic recovery per the repo convention (internal/pool/pool.go,
	// pkg/executor/executor.go). This runs on every PAM session open, so an
	// unrecovered panic here would take the whole agent down from the login path.
	defer func() {
		if r := recover(); r != nil {
			log.Error().Interface("panic", r).Msg("Auth socket request handler panicked")
		}
		_ = unixConn.Close() // Closing on every exit lets PAM read EOF and fail open at once.
	}()

	peer, ok := am.verifyPeer(unixConn)
	if !ok {
		return
	}

	buf := make([]byte, authSocketReadBufferSize)
	n, err := unixConn.Read(buf)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to read sudo request")
		am.sendIsAlpconResponse(unixConn, "", "", 0, 0, false)
		return
	}

	var baseReq BaseRequest
	if err := json.Unmarshal(buf[:n], &baseReq); err != nil {
		log.Warn().Err(err).Msg("Invalid JSON request")
		return
	}

	if baseReq.Type == "" {
		log.Warn().Msg("Missing or invalid type field")
		return
	}

	if !peer.skipPIDCheck && baseReq.PID != peer.pid {
		log.Warn().
			Int("peer_pid", peer.pid).
			Int("peer_uid", peer.uid).
			Int("claimed_pid", baseReq.PID).
			Str("type", baseReq.Type).
			Msg("Auth socket request claims a pid other than the peer process; dropping it")
		return
	}

	switch baseReq.Type {
	case "check_user":
		var isAlpconReq IsAlpconRequest
		if err := json.Unmarshal(buf[:n], &isAlpconReq); err != nil {
			log.Warn().Err(err).Msg("Invalid is_alpcon_request")
			am.sendIsAlpconResponse(unixConn, "", "", 0, 0, false)
			return
		}

		sid, sidOK := sessionID(isAlpconReq.PID)
		am.mu.RLock()
		session, exists := am.lookupSessionLocked(sid, sidOK, isAlpconReq.PPID)
		am.mu.RUnlock()

		if !exists {
			log.Warn().Msgf("No session found for PID %d (ppid %d, sid %d), username: %s, groupname: %s", isAlpconReq.PID, isAlpconReq.PPID, sid, isAlpconReq.Username, isAlpconReq.Groupname)
			am.sendIsAlpconResponse(unixConn, isAlpconReq.Username, isAlpconReq.Groupname, isAlpconReq.PID, isAlpconReq.PPID, false)
			return
		}

		log.Debug().Msgf("Session found for PID %d (sid %d): %s", isAlpconReq.PID, sid, session.SessionID)
		am.sendIsAlpconResponse(unixConn, isAlpconReq.Username, isAlpconReq.Groupname, isAlpconReq.PID, isAlpconReq.PPID, true)

	case "sudo_approval":
		am.handleSudoApprovalRequest(buf[:n], unixConn)

	case "session_event":
		am.handleSessionEvent(buf[:n], unixConn)

	default:
		log.Warn().Str("type", baseReq.Type).Msg("Unknown request type")
	}
}

// verifyPeer reports the peer process when it may use auth.sock. A refused
// peer gets no response, so nothing about the agent's state reaches it.
func (am *AuthManager) verifyPeer(conn net.Conn) (peerCred, bool) {
	if am.peerCreds == nil {
		log.Error().Msg("Auth socket peer check is not configured; dropping connection")
		return peerCred{}, false
	}
	peer, err := am.peerCreds(conn)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to read auth socket peer credentials; dropping connection")
		return peerCred{}, false
	}
	if !peerUIDAllowed(peer.uid, os.Geteuid()) {
		log.Warn().Int("peer_uid", peer.uid).Msg("Auth socket peer is neither root nor the agent user; dropping connection")
		return peerCred{}, false
	}
	return peer, true
}

// handleSudoApprovalRequest answers one sudo_approval request, parking the
// caller's goroutine until the server replies or the wait times out. Closing
// unixConn is the caller's job.
func (am *AuthManager) handleSudoApprovalRequest(data []byte, unixConn net.Conn) {
	var sudoApprovalReq SudoApprovalRequest
	if err := json.Unmarshal(data, &sudoApprovalReq); err != nil {
		log.Warn().Err(err).Msg("Invalid sudo_approval_request")
		am.sendSudoApprovalResponse(unixConn, sudoApprovalReq, false, "Invalid sudo_approval_request", "")
		return
	}

	sid, sidOK := sessionID(sudoApprovalReq.PID)
	am.mu.Lock()
	session, exists := am.lookupSessionLocked(sid, sidOK, sudoApprovalReq.PPID)
	blockLocalSudo := am.blockLocalSudo
	if !exists {
		// Non-WebSH session (local SSH, etc.)
		am.mu.Unlock()
		sudoApprovalReq.IsAlpconUser = false

		if blockLocalSudo {
			// block_local_sudo=true: reject all local sudo (original behavior)
			log.Debug().Msgf("Local sudo blocked by policy: %s for user %s", sudoApprovalReq.RequestID, sudoApprovalReq.Username)
			am.sendSudoApprovalResponse(unixConn, sudoApprovalReq, false, "No Authority", "")
			return
		}

		// block_local_sudo=false: allow local sudo, respect existing sudoers permissions
		log.Debug().Msgf("Local sudo approved: %s for user %s", sudoApprovalReq.RequestID, sudoApprovalReq.Username)
		am.sendSudoApprovalResponse(unixConn, sudoApprovalReq, true, "Approved", "")
		return
	}

	// Alpacon user: pidToSessionMap
	sudoApprovalReq.IsAlpconUser = true
	kind := session.effectiveKind()
	switch kind {
	case TrackerKindCommand:
		sudoApprovalReq.SessionID = ""
		sudoApprovalReq.CommandID = session.CommandID
	case TrackerKindWebsh:
		// websh (and legacy entries without Kind, normalized by effectiveKind).
		sudoApprovalReq.SessionID = session.SessionID
		sudoApprovalReq.CommandID = ""
	default:
		// Unknown kind: reject explicitly rather than silently misattribute
		// as websh. A future new Kind must be added to the switch.
		am.mu.Unlock()
		log.Warn().Str("kind", kind).Msg("Unknown tracker kind; rejecting sudo")
		am.sendSudoApprovalResponse(unixConn, sudoApprovalReq, false, "Unknown session kind", "")
		return
	}

	// A request still registered under this id belongs to a sudo process that
	// is gone, since its pid now names this one. Push it out first, so no take
	// or cleanup by id can ever reach two instances.
	displaced := am.displaceRequestLocked(sudoApprovalReq.RequestID)

	// The same command already waits for a decision in another terminal: one
	// wait per command is enough, and the server would refuse this one anyway.
	if sudoApprovalReq.HoldCapable && am.liveHoldForLocked(sudoApprovalReq) {
		am.mu.Unlock()
		am.releaseDisplaced(displaced, sudoApprovalReq)
		log.Info().Str("request_id", sudoApprovalReq.RequestID).Msg("sudo command already waits for approval; not forwarding")
		am.sendSudoApprovalResponse(unixConn, sudoApprovalReq, false, "Already waiting", sudoCodeAlreadyWaiting)
		return
	}

	sudoRequest := newSudoRequest(unixConn, sudoApprovalReq)
	sudoRequest.posting = true
	session.Requests[sudoApprovalReq.RequestID] = sudoRequest
	am.mu.Unlock()
	// Before this request's own post, so the old wait's end reaches the server
	// first and cannot end the wait this request is about to start.
	am.releaseDisplaced(displaced, sudoApprovalReq)

	log.Debug().
		Str("request_id", sudoApprovalReq.RequestID).
		Str("kind", kind).
		Str("session_id", sudoApprovalReq.SessionID).
		Str("command_id", sudoApprovalReq.CommandID).
		Bool("hold_capable", sudoApprovalReq.HoldCapable).
		Msg("Alpacon user sudo request")

	body, err := am.sendSudoRequestWithRetry(sudoApprovalReq)
	var pending *sudoHold
	isPending := false
	if err == nil {
		pending, isPending = parseApprovalPending(body)
		prepareHold(pending, sudoApprovalReq)
	}
	if early, ok := am.settlePost(sudoRequest, pending); ok {
		// A verdict arrived while the post was in flight and fits the request
		// as now classified; it is the final answer.
		_ = am.deliverVerdict(sudoRequest, early)
		return
	}
	if err != nil {
		log.Error().Err(err).Msg("Failed to send sudo_approval request after retries")
		if !am.finalizeRequest(sudoRequest, "Communication error") {
			am.awaitTakenRequest(sudoRequest)
		}
		return
	}

	log.Debug().Msgf("sudo_approval request sent via REST API, waiting for response...")

	if isPending {
		am.awaitHeldRequest(sudoRequest, pending)
		return
	}

	// Wait for response, timeout, or context cancellation
	select {
	case <-sudoRequest.done:
		// Signaled by whoever took the request: HandleSudoApprovalResponse on a
		// server response, denyPendingRequests on a locally decided deny.
		log.Debug().Str("request_id", sudoApprovalReq.RequestID).Msg("sudo_approval request answered")
	case <-time.After(sudoApprovalResponseTimeout):
		// finalizeRequest's own take under am.mu is what settles the race with the
		// response path; a separate pending check ahead of it would only reopen the
		// gap between the two locks.
		if am.finalizeRequest(sudoRequest, "Response timeout") {
			log.Warn().Msg("sudo_approval response timeout")
		} else {
			log.Debug().Msgf("sudo_approval timeout triggered but request already handled: %s", sudoApprovalReq.RequestID)
			am.awaitTakenRequest(sudoRequest)
		}
	case <-am.ctx.Done():
		log.Debug().Msg("Context cancelled, cleaning up sudo_approval connection")
		if !am.finalizeRequest(sudoRequest, "Service shutdown") {
			am.awaitTakenRequest(sudoRequest)
		}
	}
}

// awaitTakenRequest parks until whoever took this request has answered it. Takers
// signal only once they are done with the connection—after the write and the close
// on the ordinary path, and while unwinding a panicked write, where there is no
// response left to cut—so an earlier return would let the caller's deferred close
// cut a response mid-write and leave PAM an empty body to parse. The bound is there
// because a taker that died before signaling must not strand this goroutine with the
// descriptor open. It parks on the instance's own channel, so a newer request that
// reuses the id can neither release it nor be released in its place.
func (am *AuthManager) awaitTakenRequest(req *SudoRequest) {
	select {
	case <-req.done:
	case <-time.After(authSocketHandoverTimeout):
		log.Warn().Str("request_id", req.Request.RequestID).Msg("Taken sudo_approval request never signaled completion")
	}
}

func (am *AuthManager) sendIsAlpconResponse(conn net.Conn, username, groupname string, pid, ppid int, isAlpconUser bool) {
	response := IsAlpconResponse{
		Type:         "is_alpacon_response",
		Username:     username,
		Groupname:    groupname,
		PID:          pid,
		PPID:         ppid,
		IsAlpconUser: isAlpconUser,
	}

	responseJSON, err := json.Marshal(response)
	if err != nil {
		log.Error().Err(err).Msg("Failed to marshal is_alpacon_response")
		return
	}

	_ = conn.SetWriteDeadline(time.Now().Add(authSocketWriteTimeout))
	_, err = conn.Write(responseJSON)
	if err != nil {
		log.WithLevel(authSocketWriteLevel(err)).Err(err).Msg("Failed to send is_alpacon_response")
	}
}

// sendSudoApprovalResponse writes the response alpamon itself decided on, for
// every case the alpacon-server does not answer. Closing the connection is the
// caller's job.
//
// errorCode is the machine-readable code the client shows; empty omits the key,
// which is how every response alpamon decided on looked before codes existed.
func (am *AuthManager) sendSudoApprovalResponse(conn net.Conn, req SudoApprovalRequest, approved bool, reason, errorCode string) {
	response := SudoApprovalResponse{
		Type:         "sudo_approval_response",
		Username:     req.Username,
		Groupname:    req.Groupname,
		PID:          req.PID,
		PPID:         req.PPID,
		Command:      req.Command,
		IsAlpconUser: req.IsAlpconUser,
		SessionID:    req.SessionID,
		CommandID:    req.CommandID,
		RequestID:    req.RequestID,
		Approved:     approved,
		Reason:       reason,
		ErrorCode:    errorCode,
	}

	responseJSON, err := json.Marshal(response)
	if err != nil {
		log.Error().Err(err).Msg("Failed to marshal sudo_approval_response")
		return
	}

	_ = conn.SetWriteDeadline(time.Now().Add(authSocketWriteTimeout))
	_, err = conn.Write(responseJSON)
	if err != nil {
		logSudoResponseWriteError(err, req.RequestID)
	}
}

// authSocketWriteLevel downgrades a client that is already gone to a warning:
// by the time a response reaches a torn-down session, the PAM client has
// usually exited, and the write fails as a broken pipe, a reset, a closed
// socket, or authSocketWriteTimeout expiring on a peer that stopped reading.
func authSocketWriteLevel(err error) zerolog.Level {
	if errors.Is(err, syscall.EPIPE) || errors.Is(err, syscall.ECONNRESET) ||
		errors.Is(err, net.ErrClosed) || errors.Is(err, os.ErrDeadlineExceeded) {
		return zerolog.WarnLevel
	}

	return zerolog.ErrorLevel
}

func logSudoResponseWriteError(err error, requestID string) {
	log.WithLevel(authSocketWriteLevel(err)).Err(err).Str("request_id", requestID).Msg("Failed to send sudo_approval_response")
}

// HandleSudoApprovalResponse answers and closes the request it takes, the way
// finalizeRequest does for the paths alpamon answers itself; handleSudoRequest
// closes again once the released waiter returns, which is harmless. Every exit
// releases the waiter, because the take leaves nobody else able to.
func (am *AuthManager) HandleSudoApprovalResponse(response SudoApprovalResponse) error {
	log.Info().Str("request_id", response.RequestID).Bool("approved", response.Approved).Msg("Processing sudo_approval response")

	am.mu.Lock()
	sudoRequest := am.findRequestLocked(response.RequestID)
	if reason := am.mismatchLocked(response, sudoRequest); reason != "" {
		am.mu.Unlock()
		// A verdict for another request that used the same id (the id is the sudo
		// pid, which the kernel reuses). Applying it would answer the wrong command.
		log.Warn().
			Str("request_id", response.RequestID).
			Str("session_id", response.SessionID).
			Str("mismatch", reason).
			Msg("Dropped a sudo_approval response that does not match the pending request")
		return fmt.Errorf("sudo_approval response for request_id %s does not match the pending request: %s", response.RequestID, reason)
	}
	if sudoRequest != nil && sudoRequest.posting {
		// Whether the server holds this request is not known yet, so the
		// command a verdict must name is not either: settlePost decides.
		parked := len(sudoRequest.early) < maxEarlyVerdicts
		if parked {
			sudoRequest.early = append(sudoRequest.early, response)
		}
		am.mu.Unlock()
		if !parked {
			log.Warn().Str("request_id", response.RequestID).Msg("Dropped a sudo_approval response: too many arrived before the post was answered")
			return fmt.Errorf("too many sudo_approval responses for request_id %s before its post was answered", response.RequestID)
		}
		log.Debug().Str("request_id", response.RequestID).Msg("sudo_approval response arrived before the post was answered; parked")
		return nil
	}
	// Found and taken in one critical section, so the instance the match was
	// checked against is the one answered.
	if sudoRequest != nil {
		am.takeInstanceLocked(sudoRequest)
	}
	am.mu.Unlock()

	if sudoRequest == nil {
		// Routine after a timeout: the waiter already answered and deregistered.
		log.Debug().Str("request_id", response.RequestID).Msg("No pending sudo_approval request for response")

		return fmt.Errorf("no pending sudo_approval request found for request_id: %s", response.RequestID)
	}

	return am.deliverVerdict(sudoRequest, response)
}

// deliverVerdict writes the server's verdict to a request the caller took,
// closes it and releases its waiter.
func (am *AuthManager) deliverVerdict(sudoRequest *SudoRequest, response SudoApprovalResponse) error {
	// The take has no owner left to answer it, so every exit from here has to release
	// the waiter—including an early return added later between the take and the write.
	defer am.signalCompletion(sudoRequest)

	responseJSON, err := json.Marshal(response)
	if err != nil {
		log.Error().Err(err).Msg("Failed to marshal sudo_approval_response")
		return err
	}

	// The request is already deregistered, so nobody else can reclaim this
	// connection; writeMu only waits out an interim frame still going out.
	sudoRequest.writeMu.Lock()
	sudoRequest.final = true
	_ = sudoRequest.Connection.SetWriteDeadline(time.Now().Add(authSocketWriteTimeout))
	_, err = sudoRequest.Connection.Write(responseJSON)
	_ = sudoRequest.Connection.Close()
	sudoRequest.writeMu.Unlock()
	if err != nil {
		logSudoResponseWriteError(err, response.RequestID)
		return err
	}

	log.Info().Str("request_id", response.RequestID).Bool("approved", response.Approved).Str("error_code", response.ErrorCode).Msg("SudoApprovalResponse processed successfully")
	return nil
}

// AddPIDSessionMapping registers an entry for a Websh PTY session. Unset Kind,
// Requests, StartedAt and PID are filled in; CommandID is always cleared to keep
// the websh and command fields mutually exclusive per entry.
func (am *AuthManager) AddPIDSessionMapping(pid int, session *SessionInfo) {
	if session == nil {
		return
	}

	am.mu.Lock()
	// Filled in under the lock: re-registering the entry already installed for
	// this pid writes fields a concurrent lookup is reading.
	if session.Kind == "" {
		session.Kind = TrackerKindWebsh
	}
	if session.Requests == nil {
		session.Requests = make(map[string]*SudoRequest)
	}
	session.CommandID = ""
	if session.StartedAt.IsZero() {
		session.StartedAt = time.Now()
	}
	if session.PID == 0 {
		session.PID = pid
	}
	replaced := am.putSessionLocked(pid, session)
	log.Debug().
		Int("pid", pid).
		Str("kind", session.effectiveKind()).
		Str("session_id", session.SessionID).
		Msg("PID mapping added")
	am.mu.Unlock()

	am.denyPendingRequests(replaced, "Session replaced")
}

// putSessionLocked installs the entry for pid and hands the pending requests of
// the entry it displaces to the caller, who owns answering them—otherwise they
// wait out the PAM client's own timeout. Callers must hold am.mu.
func (am *AuthManager) putSessionLocked(pid int, session *SessionInfo) []*SudoRequest {
	var replaced []*SudoRequest

	if old, exists := am.pidToSessionMap[pid]; exists && old != session {
		replaced = am.takePendingRequestsLocked(old)
	}
	am.pidToSessionMap[pid] = session

	return replaced
}

func (am *AuthManager) RemovePIDSessionMapping(pid int) {
	var pending []*SudoRequest

	am.mu.Lock()
	if session, exists := am.pidToSessionMap[pid]; exists {
		delete(am.pidToSessionMap, pid)
		pending = am.takePendingRequestsLocked(session)
		log.Debug().
			Int("pid", pid).
			Str("kind", session.effectiveKind()).
			Str("session_id", session.SessionID).
			Str("command_id", session.CommandID).
			Msg("PID mapping removed")
	}
	am.mu.Unlock()

	am.denyPendingRequests(pending, "Session ended")
}

// AddPIDCommandMapping registers the root pid of a deploy shell Command
// execution so alpamon-pam can attribute a sudo call made inside the Command
// (or any descendant) to the originating Command.ID. It must be called before
// the child process can exec sudo, or sudo reaches the PAM module before the
// tracker knows about the pid. Safe to call from any goroutine.
func (am *AuthManager) AddPIDCommandMapping(pid int, commandID, username string) {
	if pid <= 0 || commandID == "" {
		return
	}
	info := &SessionInfo{
		Kind:      TrackerKindCommand,
		CommandID: commandID,
		Username:  username,
		PID:       pid,
		StartedAt: time.Now(),
		Requests:  make(map[string]*SudoRequest),
	}
	am.mu.Lock()
	replaced := am.putSessionLocked(pid, info)
	am.mu.Unlock()

	am.denyPendingRequests(replaced, "Session replaced")

	log.Debug().
		Int("pid", pid).
		Str("command_id", commandID).
		Str("username", username).
		Msg("Command PID mapping added")
}

// RemovePIDCommandMapping deletes the tracker entry for a deploy shell
// Command's root pid. It only removes the entry when it still has the
// matching command_id; callers must pass a non-empty commandID so that
// a pid reused by an unrelated entry (e.g. a legacy leftover from a
// crash) cannot be dropped accidentally.
func (am *AuthManager) RemovePIDCommandMapping(pid int, commandID string) {
	if pid <= 0 || commandID == "" {
		return
	}
	var pending []*SudoRequest

	am.mu.Lock()
	if existing, ok := am.pidToSessionMap[pid]; ok {
		if existing.effectiveKind() == TrackerKindCommand &&
			existing.CommandID == commandID {
			delete(am.pidToSessionMap, pid)
			pending = am.takePendingRequestsLocked(existing)
			log.Debug().
				Int("pid", pid).
				Str("command_id", existing.CommandID).
				Msg("Command PID mapping removed")
		}
	}
	am.mu.Unlock()

	am.denyPendingRequests(pending, "Session ended")
}

// TrackerEntry is a read-only snapshot of a tracker entry, returned by LookupPID
// so callers can inspect state without taking the AuthManager's lock.
type TrackerEntry struct {
	Kind      string
	SessionID string
	CommandID string
	Username  string
	PID       int
	StartedAt time.Time
}

// LookupPID returns a snapshot of the tracker entry for pid (if any).
// The second return value reports whether an entry was found.
func (am *AuthManager) LookupPID(pid int) (TrackerEntry, bool) {
	am.mu.RLock()
	defer am.mu.RUnlock()
	info, ok := am.pidToSessionMap[pid]
	if !ok {
		return TrackerEntry{}, false
	}
	return TrackerEntry{
		Kind:      info.effectiveKind(),
		SessionID: info.SessionID,
		CommandID: info.CommandID,
		Username:  info.Username,
		PID:       info.PID,
		StartedAt: info.StartedAt,
	}, true
}

// RegisterCommandPID is a package-level helper that registers a deploy
// shell Command root pid on the singleton AuthManager (if initialized)
// and returns an unregister closure. The closure captures the exact
// (pid, commandID) pair so callers cannot accidentally unregister the
// wrong entry, making the Register/Unregister pair leak-proof by
// construction. The returned closure is always safe to call — it is a
// no-op when the AuthManager has not been wired up yet (tests, early
// boot) or when the arguments would be rejected by
// AddPIDCommandMapping (non-positive pid, empty commandID).
func RegisterCommandPID(pid int, commandID, username string) func() {
	if authManager == nil || pid <= 0 || commandID == "" {
		return func() {}
	}
	am := authManager
	am.AddPIDCommandMapping(pid, commandID, username)
	return func() { am.RemovePIDCommandMapping(pid, commandID) }
}

// signalCompletion releases the waiter of exactly this instance. It never
// blocks: the buffer holds one signal, and the waiter only needs one. A request
// built without a channel (tests) is a no-op.
func (am *AuthManager) signalCompletion(req *SudoRequest) {
	select {
	case req.done <- struct{}{}:
	default:
	}
}

func (am *AuthManager) Stop() {
	if am.cancel != nil {
		am.cancel()
	}
	if am.listener != nil {
		_ = am.listener.Close()
	}
	// Events already acked finish reaching the disk; held ones stay there for
	// the next run. Only a manager that was started has a drain to join.
	if am.outbox != nil && am.cancel != nil {
		if !am.outbox.stop(accessOutboxStopTimeout) {
			log.Warn().Msg("Access event outbox did not stop in time")
		}
	}
}

// finalizeRequest is the single owner of the final response for a registered
// request: the PAM client parses everything it reads as one JSON document, so a
// second response breaks it. Whoever removes the request from the map under
// am.mu finalizes it, and nobody else may write to its connection. It always
// denies—approvals arrive from the server and are answered by
// HandleSudoApprovalResponse.
//
// It reports whether it took the request. A false means someone else did, and
// that taker's response may still be going out, so a caller holding the
// connection owes it an awaitTakenRequest before its own close.
func (am *AuthManager) finalizeRequest(req *SudoRequest, reason string) bool {
	am.mu.Lock()
	taken := am.takeInstanceLocked(req)
	am.mu.Unlock()

	if !taken {
		// Routine: the server response or a session teardown took the request first.
		log.Debug().
			Str("request_id", req.Request.RequestID).
			Str("reason", reason).
			Msg("No pending sudo request to finalize")
		return false
	}

	am.denyPendingRequests([]*SudoRequest{req}, reason)

	return true
}

// takeInstanceLocked deregisters req itself and reports whether it was still
// registered; takePendingRequestsLocked does the same for a whole session.
// Deregistering nowhere else is what keeps a request from being answered twice.
// It compares the instance, not the id: a newer request that reuses the id (the
// sudo pid) is never taken in the old one's place. Callers must hold am.mu.
func (am *AuthManager) takeInstanceLocked(req *SudoRequest) bool {
	for _, session := range am.pidToSessionMap {
		if session.Requests[req.Request.RequestID] == req {
			delete(session.Requests, req.Request.RequestID)
			return true
		}
	}

	return false
}

// displaceRequestLocked takes the request registered under requestID, if any,
// so a newer request with the same id can register. A held one has its id
// guarded against the old wait's late verdict in the same critical section.
// The caller owns releaseDisplaced on the result. Callers must hold am.mu.
func (am *AuthManager) displaceRequestLocked(requestID string) *SudoRequest {
	old := am.findRequestLocked(requestID)
	if old == nil {
		return nil
	}
	am.takeInstanceLocked(old)
	old.displaced = true
	if old.hold != nil {
		am.rememberEndedHoldLocked(old.Request, old.hold)
	} else {
		// Its verdict may still come (its post may even be in flight), with
		// the same id and session as the request that displaced it.
		am.rememberDisplacedLocked(old.Request)
	}
	return old
}

// releaseDisplaced closes a displaced request without writing to it (its sudo
// process is gone) and releases its waiter. A held one's end is reported to the
// server before it returns, so the caller can post newcomer's request after it,
// unless newcomer is the same wait: same session (or deploy Command), command
// and run-as user, which the server continues as one wait. Must run without
// am.mu held.
func (am *AuthManager) releaseDisplaced(old *SudoRequest, newcomer SudoApprovalRequest) {
	if old == nil {
		return
	}
	log.Warn().Str("request_id", old.Request.RequestID).
		Msg("A new sudo request reuses the id of a pending one; dropping the old one")
	old.writeMu.Lock()
	old.final = true
	if old.Connection != nil {
		_ = old.Connection.Close()
	}
	old.writeMu.Unlock()
	am.signalCompletion(old)
	if old.hold != nil && !sameWait(old.Request, newcomer) {
		am.postWaitEndedOnce(am.ctx, old.Request, old.hold)
	}
}

// sameWait reports whether a and b ask for the same decision: the same session
// (or deploy Command), command and run-as user.
func sameWait(a, b SudoApprovalRequest) bool {
	return a.SessionID == b.SessionID && a.CommandID == b.CommandID &&
		a.Command == b.Command && a.RunasUser == b.RunasUser
}

// takePendingRequestsLocked detaches a session's pending requests. They are then
// beyond finalizeRequest's reach, so the taker owns answering them, which
// denyPendingRequests does. A held one has its id guarded against the wait's
// late verdict in the same critical section. Callers must hold am.mu.
func (am *AuthManager) takePendingRequestsLocked(session *SessionInfo) []*SudoRequest {
	pending := slices.Collect(maps.Values(session.Requests))
	clear(session.Requests)
	for _, req := range pending {
		if req.hold != nil {
			am.rememberEndedHoldLocked(req.Request, req.hold)
		}
	}
	return pending
}

// denyPendingRequests answers each detached request, closes its connection, and
// releases the goroutine waiting on it—which would otherwise hold an answered
// request until its own 30s timeout. One goroutine per request is what keeps
// authSocketHandoverTimeout honest: answered in sequence, request k's signal would
// sit behind every write before it, so one peer that stopped reading pushes the
// later waiters past their bound and they close connections this loop has yet to
// write to. Must run without am.mu held: it writes to client sockets.
//
// A held request among them also has its wait reported as ended: the session
// is gone, and the server's wait would otherwise run to its own deadline.
func (am *AuthManager) denyPendingRequests(pending []*SudoRequest, reason string) {
	am.denyPendingRequestsWithCode(pending, reason, "")
	for _, req := range pending {
		// hold is stable once the request is taken: beginHold sets it only
		// on a registered request.
		if req.hold != nil {
			go am.postWaitEnded(req.Request, req.hold)
		}
	}
}

// denyPendingRequestsWithCode is denyPendingRequests with a machine-readable
// code on every deny.
func (am *AuthManager) denyPendingRequestsWithCode(pending []*SudoRequest, reason, errorCode string) {
	var wg sync.WaitGroup
	for _, req := range pending {
		wg.Go(func() {
			// handleSudoRequest's recover used to cover this work, back when
			// finalizeRequest ran it on the waiter's own stack. Off that stack, an
			// unrecovered panic takes the whole agent down instead of one request.
			defer func() {
				if r := recover(); r != nil {
					log.Error().Interface("panic", r).
						Str("request_id", req.Request.RequestID).
						Msg("Denying a pending sudo request panicked")
				}
			}()
			// Registered last so it runs first on the way out: after the write and the
			// close on the ordinary path, and during unwinding on the panic path, where
			// the write has already failed and the waiter would otherwise park out the
			// whole handover bound for a body that is never coming.
			defer am.signalCompletion(req)
			if req.Connection != nil {
				// writeMu is released by its own defer: on the panic path the
				// signal above must not find it still held.
				req.writeMu.Lock()
				defer req.writeMu.Unlock()
				req.final = true
				am.sendSudoApprovalResponse(req.Connection, req.Request, false, reason, errorCode)
				_ = req.Connection.Close()
			}
		})
	}
	wg.Wait()
}
