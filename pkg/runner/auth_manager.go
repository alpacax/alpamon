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
	"sync/atomic"
	"syscall"
	"time"

	"github.com/alpacax/alpamon/v2/internal/retry"
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
}

type SudoApprovalResponse struct {
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
	Approved     bool   `json:"approved"`
	Reason       string `json:"reason"`
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
	mu                 sync.RWMutex
	ctx                context.Context
	cancel             context.CancelFunc
	pidToSessionMap    map[int]*SessionInfo
	controlClient      *ControlClient
	listener           net.Listener
	completionChannels map[string]chan struct{}
	session            *scheduler.Session
	blockLocalSudo     bool
	detectLocalAccess  bool
	// emitAccessEventFn overrides emitAccessEvent in tests; nil means
	// the real emitter is used.
	emitAccessEventFn func(NonAlpaconAccessEvent)
	// emitSem bounds concurrent access-event emit goroutines. Each emit
	// can hold a slot for roughly authRetryTimeout plus one HTTP timeout —
	// retry.Retry checks MaxElapsedTime only after an attempt returns, so the
	// attempt in flight at the 25s mark still runs its full 10s budget, giving
	// a ~35s worst case. A login burst could otherwise spawn goroutines
	// without limit. A full channel means the budget is exhausted and the
	// event is dropped (non-blocking, never blocks the ack path).
	emitSem chan struct{}
	// accessEndpointSeen latches once the access event endpoint has answered
	// 2xx on this agent, which is what lets a later 404 be reported instead of
	// being read as "Phase 2 not deployed yet". Per-manager rather than
	// package-level so tests cannot leak the latch into one another.
	accessEndpointSeen atomic.Bool
}

const (
	authRetryInitialInterval = 1 * time.Second
	authRetryMaxInterval     = 10 * time.Second
	authRetryTimeout         = 25 * time.Second // Less than PAM 30s timeout
	// authSocketWriteTimeout bounds every write to auth.sock. Session teardown and
	// Command registration deny leftover requests inline, so a peer that stopped
	// reading must not stall them.
	authSocketWriteTimeout = 5 * time.Second
	// emitConcurrencyLimit caps in-flight access-event emit goroutines.
	emitConcurrencyLimit = 16
	// authSocketReadBufferSize bounds a single auth.sock request. The largest
	// frame is a session_event carrying all four PAM items at alpamon-pam's
	// PAM_ITEM_MAX_LEN of 256 bytes: ~1.1 KB of plain ASCII, but jansson
	// escapes control bytes 6:1, so the encoded form can reach ~6.5 KB. The
	// previous 1 KB truncated those into a JSON parse error, which closed the
	// connection and lost the audit event.
	authSocketReadBufferSize = 8192
)

var (
	authManager     *AuthManager
	authManagerOnce sync.Once
)

func GetAuthManager(controlClient *ControlClient, session *scheduler.Session) *AuthManager {
	authManagerOnce.Do(func() {
		authManager = &AuthManager{
			pidToSessionMap:    make(map[int]*SessionInfo),
			completionChannels: make(map[string]chan struct{}),
			session:            session,
			emitSem:            make(chan struct{}, emitConcurrencyLimit),
		}
	})

	if authManager.controlClient == nil {
		authManager.controlClient = controlClient
	}

	if authManager.completionChannels == nil {
		authManager.completionChannels = make(map[string]chan struct{})
	}

	if authManager.session == nil {
		authManager.session = session
	}

	if authManager.emitSem == nil {
		authManager.emitSem = make(chan struct{}, emitConcurrencyLimit)
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

func (am *AuthManager) Start(ctx context.Context) {
	am.ctx, am.cancel = context.WithCancel(ctx)

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

	if _, err := os.Stat(socketPath); err == nil {
		_ = os.Remove(socketPath)
	}

	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		return fmt.Errorf("socket listen error: %w", err)
	}

	if err := os.Chmod(socketPath, 0600); err != nil {
		return fmt.Errorf("failed to set socket permissions: %w", err)
	}

	if os.Getuid() == 0 {
		if err := os.Chown(socketPath, 0, 0); err != nil {
			return fmt.Errorf("failed to set socket ownership: %w", err)
		}
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

func (am *AuthManager) sendSudoRequestWithRetry(req SudoApprovalRequest) error {
	b := &retry.ExponentialBackoff{
		InitialInterval: authRetryInitialInterval,
		MaxInterval:     authRetryMaxInterval,
		MaxElapsedTime:  authRetryTimeout,
	}

	ctx, cancel := context.WithTimeout(am.ctx, authRetryTimeout)
	defer cancel()

	return retry.Retry(ctx, b, am.createSendOperation(ctx, req))
}

func (am *AuthManager) createSendOperation(ctx context.Context, req SudoApprovalRequest) func() error {
	return func() error {
		select {
		case <-ctx.Done():
			return retry.Permanent(ctx.Err())
		default:
			if am.session == nil {
				return fmt.Errorf("HTTP session not available")
			}

			// Deploy shell (Command) sudo requests go to the session-less
			// endpoint so the server can resolve the IAM user via command_id.
			var url string
			if req.CommandID != "" && req.SessionID == "" {
				url = "/api/sudo/approval/"
			} else {
				url = fmt.Sprintf("/api/websh/sessions/%s/sudo-approval/", req.SessionID)
			}
			_, statusCode, err := am.session.Post(url, req, 10)
			if err != nil {
				log.Warn().Err(err).Msg("Failed to send sudo request via REST API, will retry")
				return err
			}

			if statusCode < 200 || statusCode >= 300 {
				log.Warn().Int("status_code", statusCode).Msgf("Sudo request failed with status %d, will retry", statusCode)
				return fmt.Errorf("sudo request failed with status code: %d", statusCode)
			}

			log.Debug().Msg("Sudo request sent successfully via REST API")
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
	// This runs on every PAM session open, so an unrecovered panic here would
	// take the whole agent down from the login path.
	defer func() {
		if r := recover(); r != nil {
			log.Error().Interface("panic", r).Msg("Auth socket request handler panicked")
		}
		_ = unixConn.Close() // Closing on every exit lets PAM read EOF and fail open at once.
	}()

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

func (am *AuthManager) handleSudoApprovalRequest(data []byte, unixConn net.Conn) {
	var sudoApprovalReq SudoApprovalRequest
	if err := json.Unmarshal(data, &sudoApprovalReq); err != nil {
		log.Warn().Err(err).Msg("Invalid sudo_approval_request")
		am.sendSudoApprovalResponse(unixConn, sudoApprovalReq, false, "Invalid sudo_approval_request")
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
			am.sendSudoApprovalResponse(unixConn, sudoApprovalReq, false, "No Authority")
			return
		}

		// block_local_sudo=false: allow local sudo, respect existing sudoers permissions
		log.Debug().Msgf("Local sudo approved: %s for user %s", sudoApprovalReq.RequestID, sudoApprovalReq.Username)
		am.sendSudoApprovalResponse(unixConn, sudoApprovalReq, true, "Approved")
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
		am.sendSudoApprovalResponse(unixConn, sudoApprovalReq, false, "Unknown session kind")
		return
	}

	session.Requests[sudoApprovalReq.RequestID] = &SudoRequest{
		Connection: unixConn,
		Request:    sudoApprovalReq,
	}
	// Created under the registration's lock: a teardown in between would signal a
	// channel that does not exist yet, leaving this goroutine to its full timeout.
	completionChan := am.newCompletionChannelLocked(sudoApprovalReq.RequestID)
	am.mu.Unlock()
	defer am.removeCompletionChannel(sudoApprovalReq.RequestID)

	log.Debug().
		Str("request_id", sudoApprovalReq.RequestID).
		Str("kind", kind).
		Str("session_id", sudoApprovalReq.SessionID).
		Str("command_id", sudoApprovalReq.CommandID).
		Msg("Alpacon user sudo request")

	if err := am.sendSudoRequestWithRetry(sudoApprovalReq); err != nil {
		log.Error().Err(err).Msg("Failed to send sudo_approval request after retries")
		am.finalizeRequest(sudoApprovalReq.RequestID, "Communication error")
		return
	}

	log.Debug().Msgf("sudo_approval request sent via REST API, waiting for response...")

	// Wait for response, timeout, or context cancellation
	select {
	case <-completionChan:
		// Signaled by whoever took the request: HandleSudoApprovalResponse on a
		// server response, denyPendingRequests on a locally decided deny.
		log.Debug().Str("request_id", sudoApprovalReq.RequestID).Msg("sudo_approval request answered")
	case <-time.After(30 * time.Second):
		// The take under am.mu is what settles the race; this check only keeps the
		// timeout from warning about a request the response path already took.
		if am.isRequestPending(sudoApprovalReq.RequestID) {
			log.Warn().Msg("sudo_approval response timeout")
			am.finalizeRequest(sudoApprovalReq.RequestID, "Response timeout")
		} else {
			log.Debug().Msgf("sudo_approval timeout triggered but request already handled: %s", sudoApprovalReq.RequestID)
		}
	case <-am.ctx.Done():
		log.Debug().Msg("Context cancelled, cleaning up sudo_approval connection")
		if am.isRequestPending(sudoApprovalReq.RequestID) {
			am.finalizeRequest(sudoApprovalReq.RequestID, "Service shutdown")
		}
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
func (am *AuthManager) sendSudoApprovalResponse(conn net.Conn, req SudoApprovalRequest, approved bool, reason string) {
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
// closes again once the released waiter returns, which is harmless.
func (am *AuthManager) HandleSudoApprovalResponse(response SudoApprovalResponse) error {
	log.Info().Str("request_id", response.RequestID).Bool("approved", response.Approved).Msg("Processing sudo_approval response")

	am.mu.Lock()
	sudoRequest := am.takeRequestLocked(response.RequestID)
	am.mu.Unlock()

	if sudoRequest == nil {
		// Routine after a timeout: the waiter already answered and deregistered.
		log.Debug().Str("request_id", response.RequestID).Msg("No pending sudo_approval request for response")

		return fmt.Errorf("no pending sudo_approval request found for request_id: %s", response.RequestID)
	}

	responseJSON, err := json.Marshal(response)
	if err != nil {
		log.Error().Err(err).Msg("Failed to marshal sudo_approval_response")
		return err
	}

	// The request is already deregistered, so nobody else can reclaim this
	// connection, and the waiter has to be released whether the write landed or not.
	_ = sudoRequest.Connection.SetWriteDeadline(time.Now().Add(authSocketWriteTimeout))
	_, err = sudoRequest.Connection.Write(responseJSON)
	_ = sudoRequest.Connection.Close()
	am.signalCompletion(response.RequestID)
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
	am.mu.Unlock()

	am.denyPendingRequests(replaced, "Session replaced")
}

// putSessionLocked installs the entry for pid and hands the pending requests of
// the entry it displaces to the caller, who owns answering them—otherwise they
// wait out the PAM client's own timeout. Callers must hold am.mu.
func (am *AuthManager) putSessionLocked(pid int, session *SessionInfo) []*SudoRequest {
	var replaced []*SudoRequest

	if old, exists := am.pidToSessionMap[pid]; exists && old != session {
		replaced = takePendingRequestsLocked(old)
	}
	am.pidToSessionMap[pid] = session

	return replaced
}

func (am *AuthManager) RemovePIDSessionMapping(pid int) {
	var pending []*SudoRequest

	am.mu.Lock()
	if session, exists := am.pidToSessionMap[pid]; exists {
		delete(am.pidToSessionMap, pid)
		pending = takePendingRequestsLocked(session)
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
			pending = takePendingRequestsLocked(existing)
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

// newCompletionChannelLocked registers the channel its waiter parks on. Capacity 1
// is load-bearing: signalCompletion sends without blocking, so an unbuffered
// channel drops a signal that beats the waiter's select. Callers must hold am.mu;
// the channel has to appear in the same critical section as its request.
func (am *AuthManager) newCompletionChannelLocked(requestID string) chan struct{} {
	ch := make(chan struct{}, 1)
	am.completionChannels[requestID] = ch

	return ch
}

func (am *AuthManager) removeCompletionChannel(requestID string) {
	am.mu.Lock()
	delete(am.completionChannels, requestID)
	am.mu.Unlock()
}

func (am *AuthManager) signalCompletion(requestID string) {
	am.mu.RLock()
	ch, exists := am.completionChannels[requestID]
	am.mu.RUnlock()

	if exists {
		select {
		case ch <- struct{}{}:
		default:
			// Already signaled; the waiter only needs one.
		}
	}
}

// isRequestPending checks if a sudo request is still pending (not yet handled).
// Used to prevent race condition between timeout and response handling.
func (am *AuthManager) isRequestPending(requestID string) bool {
	am.mu.RLock()
	defer am.mu.RUnlock()

	for _, session := range am.pidToSessionMap {
		if _, exists := session.Requests[requestID]; exists {
			return true
		}
	}

	return false
}

func (am *AuthManager) Stop() {
	if am.cancel != nil {
		am.cancel()
	}
	if am.listener != nil {
		_ = am.listener.Close()
	}
}

// finalizeRequest is the single owner of the final response for a registered
// request: the PAM client parses everything it reads as one JSON document, so a
// second response breaks it. Whoever removes the request from the map under
// am.mu finalizes it, and nobody else may write to its connection. It always
// denies—approvals arrive from the server and are answered by
// HandleSudoApprovalResponse.
func (am *AuthManager) finalizeRequest(requestID, reason string) {
	am.mu.Lock()
	req := am.takeRequestLocked(requestID)
	am.mu.Unlock()

	if req == nil {
		// Routine: the server response or a session teardown took the request first.
		log.Debug().
			Str("request_id", requestID).
			Str("reason", reason).
			Msg("No pending sudo request to finalize")
		return
	}

	am.denyPendingRequests([]*SudoRequest{req}, reason)
}

// takeRequestLocked deregisters one request by id and hands its response to the
// caller; takePendingRequestsLocked does the same for a whole session.
// Deregistering nowhere else is what keeps a request from being answered twice.
// Callers must hold am.mu.
func (am *AuthManager) takeRequestLocked(requestID string) *SudoRequest {
	for _, session := range am.pidToSessionMap {
		if req, exists := session.Requests[requestID]; exists {
			delete(session.Requests, requestID)
			return req
		}
	}

	return nil
}

// takePendingRequestsLocked detaches a session's pending requests. They are then
// beyond finalizeRequest's reach, so the taker owns answering them.
// Callers must hold am.mu.
func takePendingRequestsLocked(session *SessionInfo) []*SudoRequest {
	pending := slices.Collect(maps.Values(session.Requests))
	clear(session.Requests)
	return pending
}

// denyPendingRequests answers each detached request, closes its connection, and
// releases the goroutine waiting on it—which would otherwise hold an answered
// request until its own 30s timeout. Must run without am.mu held: signalCompletion
// takes it.
func (am *AuthManager) denyPendingRequests(pending []*SudoRequest, reason string) {
	for _, req := range pending {
		if req.Connection != nil {
			am.sendSudoApprovalResponse(req.Connection, req.Request, false, reason)
			_ = req.Connection.Close()
		}
		am.signalCompletion(req.Request.RequestID)
	}
}
