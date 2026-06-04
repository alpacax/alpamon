package runner

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/alpacax/alpamon/v2/internal/retry"
	"github.com/alpacax/alpamon/v2/pkg/scheduler"
	"github.com/alpacax/alpamon/v2/pkg/utils"
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
	RequestID  string
	Connection net.Conn
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
	localSudoRequests  map[string]*SudoRequest
	completionChannels map[string]chan struct{}
	session            *scheduler.Session
	blockLocalSudo     bool
}

const (
	authRetryInitialInterval = 1 * time.Second
	authRetryMaxInterval     = 10 * time.Second
	authRetryTimeout         = 25 * time.Second // Less than PAM 30s timeout
)

var (
	authManager     *AuthManager
	authManagerOnce sync.Once
)

func GetAuthManager(controlClient *ControlClient, session *scheduler.Session) *AuthManager {
	authManagerOnce.Do(func() {
		authManager = &AuthManager{
			pidToSessionMap:    make(map[int]*SessionInfo),
			localSudoRequests:  make(map[string]*SudoRequest),
			completionChannels: make(map[string]chan struct{}),
			session:            session,
		}
	})

	if authManager.controlClient == nil {
		authManager.controlClient = controlClient
	}

	if authManager.localSudoRequests == nil {
		authManager.localSudoRequests = make(map[string]*SudoRequest)
	}

	if authManager.completionChannels == nil {
		authManager.completionChannels = make(map[string]chan struct{})
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
	buf := make([]byte, 1024)
	n, err := unixConn.Read(buf)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to read sudo request")
		am.sendIsAlpconResponse(unixConn, "", "", 0, 0, false)
		return
	}

	var baseReq BaseRequest
	if err := json.Unmarshal(buf[:n], &baseReq); err != nil {
		log.Warn().Err(err).Msg("Invalid JSON request")
		_ = unixConn.Close()
		return
	}

	if baseReq.Type == "" {
		log.Warn().Msg("Missing or invalid type field")
		_ = unixConn.Close()
		return
	}

	switch baseReq.Type {
	case "check_user":
		var isAlpconReq IsAlpconRequest
		if err := json.Unmarshal(buf[:n], &isAlpconReq); err != nil {
			log.Warn().Err(err).Msg("Invalid is_alpcon_request")
			am.sendIsAlpconResponse(unixConn, "", "", 0, 0, false)
			_ = unixConn.Close()
			return
		}

		sid, sidOK := sessionID(isAlpconReq.PID)
		am.mu.RLock()
		session, exists := am.lookupSessionLocked(sid, sidOK, isAlpconReq.PPID)
		am.mu.RUnlock()

		if !exists {
			log.Warn().Msgf("No session found for PID %d (ppid %d, sid %d), username: %s, groupname: %s", isAlpconReq.PID, isAlpconReq.PPID, sid, isAlpconReq.Username, isAlpconReq.Groupname)
			am.sendIsAlpconResponse(unixConn, isAlpconReq.Username, isAlpconReq.Groupname, isAlpconReq.PID, isAlpconReq.PPID, false)
			_ = unixConn.Close()
			return
		}

		log.Debug().Msgf("Session found for PID %d (sid %d): %s", isAlpconReq.PID, sid, session.SessionID)
		am.sendIsAlpconResponse(unixConn, isAlpconReq.Username, isAlpconReq.Groupname, isAlpconReq.PID, isAlpconReq.PPID, true)
		_ = unixConn.Close()

	case "sudo_approval":
		am.handleSudoApprovalRequest(buf[:n], unixConn)

	default:
		log.Warn().Str("type", baseReq.Type).Msg("Unknown request type")
		_ = unixConn.Close()
	}
}

func (am *AuthManager) handleSudoApprovalRequest(data []byte, unixConn net.Conn) {
	var sudoApprovalReq SudoApprovalRequest
	if err := json.Unmarshal(data, &sudoApprovalReq); err != nil {
		log.Warn().Err(err).Msg("Invalid sudo_approval_request")
		am.sendSudoApprovalResponse(unixConn, sudoApprovalReq, false, "Invalid sudo_approval_request")
		_ = unixConn.Close()
		return
	}

	// Create completion channel to signal when response is received
	completionChan := make(chan struct{})

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
			_ = unixConn.Close()
			return
		}

		// block_local_sudo=false: allow local sudo, respect existing sudoers permissions
		log.Debug().Msgf("Local sudo approved: %s for user %s", sudoApprovalReq.RequestID, sudoApprovalReq.Username)
		am.sendSudoApprovalResponse(unixConn, sudoApprovalReq, true, "Approved")
		_ = unixConn.Close()
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
		_ = unixConn.Close()
		return
	}

	session.Requests[sudoApprovalReq.RequestID] = &SudoRequest{
		RequestID:  sudoApprovalReq.RequestID,
		Connection: unixConn,
	}
	am.mu.Unlock()

	log.Debug().
		Str("request_id", sudoApprovalReq.RequestID).
		Str("kind", kind).
		Str("session_id", sudoApprovalReq.SessionID).
		Str("command_id", sudoApprovalReq.CommandID).
		Msg("Alpacon user sudo request")

	// Store completion channel for this request
	am.storeCompletionChannel(sudoApprovalReq.RequestID, completionChan)

	// Send Sudo Approval request to the alpacon-server with retry
	if err := am.sendSudoRequestWithRetry(sudoApprovalReq); err != nil {
		log.Error().Err(err).Msg("Failed to send sudo_approval request after retries")
		am.sendSudoApprovalResponse(unixConn, sudoApprovalReq, false, "Communication error")
		am.cleanupTimeoutRequest(sudoApprovalReq.RequestID, false, "Communication error")
		am.removeCompletionChannel(sudoApprovalReq.RequestID)
		_ = unixConn.Close()
		return
	}

	log.Debug().Msgf("sudo_approval request sent via REST API, waiting for response...")

	// Wait for response, timeout, or context cancellation
	select {
	case <-completionChan:
		// Response received and processed by HandleSudoApprovalResponse
		log.Debug().Msgf("sudo_approval response received for request %s", sudoApprovalReq.RequestID)
	case <-time.After(30 * time.Second):
		// Prevent race condition: check if request still exists before cleanup
		// (HandleSudoApprovalResponse may have already processed it)
		if am.isRequestPending(sudoApprovalReq.RequestID) {
			log.Warn().Msg("sudo_approval response timeout")
			am.cleanupTimeoutRequest(sudoApprovalReq.RequestID, false, "Response timeout")
		} else {
			log.Debug().Msgf("sudo_approval timeout triggered but request already handled: %s", sudoApprovalReq.RequestID)
		}
	case <-am.ctx.Done():
		log.Debug().Msg("Context cancelled, cleaning up sudo_approval connection")
		if am.isRequestPending(sudoApprovalReq.RequestID) {
			am.cleanupTimeoutRequest(sudoApprovalReq.RequestID, false, "Service shutdown")
		}
	}
	am.removeCompletionChannel(sudoApprovalReq.RequestID)
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

	_, err = conn.Write(responseJSON)
	if err != nil {
		log.Error().Err(err).Msg("Failed to send is_alpacon_response")
		return
	}
}

// sendSudoApprovalResponse is used when there is something wrong sending the sudo approval request to the alpacon-server
func (am *AuthManager) sendSudoApprovalResponse(conn net.Conn, sudo_approval_req SudoApprovalRequest, approved bool, reason string) {
	response := SudoApprovalResponse{
		Type:         "sudo_approval_response",
		Username:     sudo_approval_req.Username,
		Groupname:    sudo_approval_req.Groupname,
		PID:          sudo_approval_req.PID,
		PPID:         sudo_approval_req.PPID,
		Command:      sudo_approval_req.Command,
		IsAlpconUser: sudo_approval_req.IsAlpconUser,
		SessionID:    sudo_approval_req.SessionID,
		CommandID:    sudo_approval_req.CommandID,
		RequestID:    sudo_approval_req.RequestID,
		Approved:     approved,
		Reason:       reason,
	}

	responseJSON, err := json.Marshal(response)
	if err != nil {
		log.Error().Err(err).Msg("Failed to marshal sudo_approval_response")
		return
	}

	_, err = conn.Write(responseJSON)
	if err != nil {
		log.Error().Err(err).Msg("Failed to send sudo_approval_response")
		return
	}
}

// HandleSudoApprovalResponse is used to handle the sudo_approval response from the alpacon-server
func (am *AuthManager) HandleSudoApprovalResponse(response SudoApprovalResponse) error {
	log.Info().Str("request_id", response.RequestID).Bool("approved", response.Approved).Msg("Processing sudo_approval response")

	am.mu.Lock()
	var sudoRequest *SudoRequest

	// 1. find in alpacon user requests
	for _, session := range am.pidToSessionMap {
		if req, exists := session.Requests[response.RequestID]; exists {
			delete(session.Requests, response.RequestID)
			sudoRequest = req
			log.Debug().Msgf("Found Alpacon user request for ID: %s", response.RequestID)
			break
		}
	}

	// 2. find in local user requests
	if sudoRequest == nil {
		if req, exists := am.localSudoRequests[response.RequestID]; exists {
			delete(am.localSudoRequests, response.RequestID)
			sudoRequest = req
			log.Debug().Msgf("Found local user request for ID: %s", response.RequestID)
		} else {
			log.Debug().Msgf("Request ID %s not found in localSudoRequests", response.RequestID)
		}
	}
	am.mu.Unlock()

	if sudoRequest == nil {
		am.mu.RLock()
		log.Debug().Msgf("Current localSudoRequests: %+v", am.localSudoRequests)
		for _, session := range am.pidToSessionMap {
			log.Debug().Msgf("Session %s requests: %+v", session.SessionID, session.Requests)
		}
		am.mu.RUnlock()

		return fmt.Errorf("no pending sudo_approval request found for request_id: %s", response.RequestID)
	}

	responseJSON, err := json.Marshal(response)
	if err != nil {
		log.Error().Err(err).Msg("Failed to marshal sudo_approval_response")
		return err
	}

	_, err = sudoRequest.Connection.Write(responseJSON)
	if err != nil {
		if strings.Contains(err.Error(), "broken pipe") || strings.Contains(err.Error(), "EPIPE") {
			log.Warn().Err(err).Str("request_id", response.RequestID).
				Msg("Unix socket broken pipe - client disconnected (expected if timeout)")
		} else {
			log.Error().Err(err).Msg("Failed to send sudo_approval_response")
		}
		return err
	}

	_ = sudoRequest.Connection.Close()

	// Signal completion to unblock the waiting goroutine
	am.signalCompletion(response.RequestID)

	log.Info().Str("request_id", response.RequestID).Bool("approved", response.Approved).Str("error_code", response.ErrorCode).Msg("SudoApprovalResponse processed successfully")
	return nil
}

// AddPIDSessionMapping registers an entry for a Websh PTY session.
// Kind and StartedAt are filled in when unset so callers don't have to
// remember to populate them; CommandID is always cleared to keep the
// websh/command fields mutually exclusive per entry.
func (am *AuthManager) AddPIDSessionMapping(pid int, session *SessionInfo) {
	if session == nil {
		return
	}
	if session.Kind == "" {
		session.Kind = TrackerKindWebsh
	}
	session.CommandID = ""
	if session.StartedAt.IsZero() {
		session.StartedAt = time.Now()
	}
	if session.PID == 0 {
		session.PID = pid
	}
	am.mu.Lock()
	am.pidToSessionMap[pid] = session
	am.mu.Unlock()
}

func (am *AuthManager) RemovePIDSessionMapping(pid int) {
	am.mu.Lock()
	if session, exists := am.pidToSessionMap[pid]; exists {
		delete(am.pidToSessionMap, pid)
		log.Debug().
			Int("pid", pid).
			Str("kind", session.effectiveKind()).
			Str("session_id", session.SessionID).
			Str("command_id", session.CommandID).
			Msg("PID mapping removed")
	}
	am.mu.Unlock()
}

// AddPIDCommandMapping registers the root pid of a deploy shell Command
// execution so alpamon-pam can attribute a sudo call made inside the
// Command (or any descendant) to the originating Command.ID. It must be
// called before the child process can exec sudo to avoid a race where
// sudo arrives at the PAM module before the tracker knows about the pid.
//
// Concurrency: multiple Commands run in parallel with distinct root pids,
// so entries never collide. Safe to call from any goroutine.
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
	am.pidToSessionMap[pid] = info
	am.mu.Unlock()
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
	am.mu.Lock()
	if existing, ok := am.pidToSessionMap[pid]; ok {
		if existing.effectiveKind() == TrackerKindCommand &&
			existing.CommandID == commandID {
			delete(am.pidToSessionMap, pid)
			log.Debug().
				Int("pid", pid).
				Str("command_id", existing.CommandID).
				Msg("Command PID mapping removed")
		}
	}
	am.mu.Unlock()
}

// TrackerEntry is a read-only snapshot of a tracker entry, returned by
// LookupPID for callers (e.g. tests) that need to inspect state without
// taking the AuthManager's lock themselves.
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

func (am *AuthManager) storeCompletionChannel(requestID string, ch chan struct{}) {
	am.mu.Lock()
	am.completionChannels[requestID] = ch
	am.mu.Unlock()
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
			// Channel already signaled or closed
		}
	}
}

// isRequestPending checks if a sudo request is still pending (not yet handled).
// Used to prevent race condition between timeout and response handling.
func (am *AuthManager) isRequestPending(requestID string) bool {
	am.mu.RLock()
	defer am.mu.RUnlock()

	// Check alpacon user requests
	for _, session := range am.pidToSessionMap {
		if _, exists := session.Requests[requestID]; exists {
			return true
		}
	}

	// Check local user requests
	if _, exists := am.localSudoRequests[requestID]; exists {
		return true
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

func (am *AuthManager) cleanupTimeoutRequest(requestID string, approved bool, reason string) {
	am.mu.Lock()

	// 1. Alpacon user
	for _, session := range am.pidToSessionMap {
		if req, exists := session.Requests[requestID]; exists {
			delete(session.Requests, requestID)
			am.mu.Unlock()
			if req.Connection != nil {
				am.sendSudoApprovalResponse(req.Connection, SudoApprovalRequest{RequestID: requestID}, approved, reason)
				_ = req.Connection.Close()
			}
			return
		}
	}

	// 2. Local user
	if req, exists := am.localSudoRequests[requestID]; exists {
		delete(am.localSudoRequests, requestID)
		am.mu.Unlock()
		if req.Connection != nil {
			am.sendSudoApprovalResponse(req.Connection, SudoApprovalRequest{RequestID: requestID}, approved, reason)
			_ = req.Connection.Close()
		}
		return
	}

	am.mu.Unlock()
	log.Warn().Msgf("Timeout request not found: %s", requestID)
}
