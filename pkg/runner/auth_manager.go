package runner

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/alpacax/alpamon/pkg/scheduler"
	"github.com/cenkalti/backoff"
	"github.com/rs/zerolog/log"
)

type SessionInfo struct {
	SessionID string
	PID       int
	PtyClient *PtyClient
	Requests  map[string]*SudoRequest
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
	SessionID    string `json:"session_id"`
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
	SessionID    string `json:"session_id"`
	Approved     bool   `json:"approved"`
	Reason       string `json:"reason"`
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
	const socketPath = "/var/run/alpamon/auth.sock"

	// systemd tmpfile will manage the /var/run/alpamon directory
	// No need to create directory manually

	if _, err := os.Stat(socketPath); err == nil {
		os.Remove(socketPath)
	}

	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		return fmt.Errorf("socket listen error: %w", err)
	}

	if err := os.Chmod(socketPath, 0600); err != nil {
		return fmt.Errorf("failed to set socket permissions: %w", err)
	}

	if err := os.Chown(socketPath, 0, 0); err != nil {
		return fmt.Errorf("failed to set socket ownership: %w", err)
	}

	log.Info().Msgf("Socket created with permissions 600 (root only)")

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
	retryBackoff := backoff.NewExponentialBackOff()
	retryBackoff.InitialInterval = authRetryInitialInterval
	retryBackoff.MaxInterval = authRetryMaxInterval
	retryBackoff.MaxElapsedTime = authRetryTimeout
	retryBackoff.RandomizationFactor = 0

	ctx, cancel := context.WithTimeout(am.ctx, authRetryTimeout)
	defer cancel()

	operation := am.createSendOperation(ctx, req)
	return backoff.Retry(operation, backoff.WithContext(retryBackoff, ctx))
}

func (am *AuthManager) createSendOperation(ctx context.Context, req SudoApprovalRequest) func() error {
	return func() error {
		select {
		case <-ctx.Done():
			return backoff.Permanent(ctx.Err())
		default:
			if am.session == nil {
				return fmt.Errorf("HTTP session not available")
			}

			url := fmt.Sprintf("/api/websh/sessions/%s/sudo-approval/", req.SessionID)
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
		unixConn.Close()
		return
	}

	if baseReq.Type == "" {
		log.Warn().Msg("Missing or invalid type field")
		unixConn.Close()
		return
	}

	switch baseReq.Type {
	case "check_user":
		var isAlpconReq IsAlpconRequest
		if err := json.Unmarshal(buf[:n], &isAlpconReq); err != nil {
			log.Warn().Err(err).Msg("Invalid is_alpcon_request")
			am.sendIsAlpconResponse(unixConn, "", "", 0, 0, false)
			unixConn.Close()
			return
		}

		am.mu.RLock()
		session, exists := am.pidToSessionMap[isAlpconReq.PPID]
		am.mu.RUnlock()

		if !exists {
			log.Warn().Msgf("No session found for PID %d, username: %s, groupname: %s", isAlpconReq.PPID, isAlpconReq.Username, isAlpconReq.Groupname)
			am.sendIsAlpconResponse(unixConn, isAlpconReq.Username, isAlpconReq.Groupname, isAlpconReq.PID, isAlpconReq.PPID, false)
			unixConn.Close()
			return
		}

		log.Debug().Msgf("Session found for PID %d: %s", isAlpconReq.PPID, session.SessionID)
		am.sendIsAlpconResponse(unixConn, isAlpconReq.Username, isAlpconReq.Groupname, isAlpconReq.PID, isAlpconReq.PPID, true)
		unixConn.Close()

	case "sudo_approval":
		am.handleSudoApprovalRequest(buf[:n], unixConn)

	default:
		log.Warn().Str("type", baseReq.Type).Msg("Unknown request type")
		unixConn.Close()
	}
}

func (am *AuthManager) handleSudoApprovalRequest(data []byte, unixConn net.Conn) {
	var sudoApprovalReq SudoApprovalRequest
	if err := json.Unmarshal(data, &sudoApprovalReq); err != nil {
		log.Warn().Err(err).Msg("Invalid sudo_approval_request")
		am.sendSudoApprovalResponse(unixConn, sudoApprovalReq, false, "Invalid sudo_approval_request")
		unixConn.Close()
		return
	}

	// Create completion channel to signal when response is received
	completionChan := make(chan struct{})

	am.mu.Lock()
	session, exists := am.pidToSessionMap[sudoApprovalReq.PPID]
	if !exists {
		// Local user: reject immediately without sending to server
		// Server would reject anyway (servers/consumer.py:217-228)
		am.mu.Unlock()
		sudoApprovalReq.IsAlpconUser = false

		log.Debug().Msgf("Local user sudo request rejected: %s for user %s", sudoApprovalReq.RequestID, sudoApprovalReq.Username)
		am.sendSudoApprovalResponse(unixConn, sudoApprovalReq, false, "No Authority")
		unixConn.Close()
		return
	}

	// Alpacon user: pidToSessionMap
	sudoApprovalReq.IsAlpconUser = true
	sudoApprovalReq.SessionID = session.SessionID

	session.Requests[sudoApprovalReq.RequestID] = &SudoRequest{
		RequestID:  sudoApprovalReq.RequestID,
		Connection: unixConn,
	}
	am.mu.Unlock()

	log.Debug().Msgf("Alpacon user sudo request: %s for session %s", sudoApprovalReq.RequestID, session.SessionID)

	// Store completion channel for this request
	am.storeCompletionChannel(sudoApprovalReq.RequestID, completionChan)

	// Send Sudo Approval request to the alpacon-server with retry
	if err := am.sendSudoRequestWithRetry(sudoApprovalReq); err != nil {
		log.Error().Err(err).Msg("Failed to send sudo_approval request after retries")
		am.sendSudoApprovalResponse(unixConn, sudoApprovalReq, false, "Communication error")
		am.cleanupTimeoutRequest(sudoApprovalReq.RequestID, false, "Communication error")
		am.removeCompletionChannel(sudoApprovalReq.RequestID)
		unixConn.Close()
		return
	}

	log.Debug().Msgf("sudo_approval request sent via REST API, waiting for response...")

	// Wait for response, timeout, or context cancellation
	select {
	case <-completionChan:
		// Response received and processed by HandleSudoApprovalResponse
		log.Debug().Msgf("sudo_approval response received for request %s", sudoApprovalReq.RequestID)
	case <-time.After(30 * time.Second):
		log.Warn().Msg("sudo_approval response timeout")
		am.cleanupTimeoutRequest(sudoApprovalReq.RequestID, false, "Response timeout")
	case <-am.ctx.Done():
		log.Debug().Msg("Context cancelled, cleaning up sudo_approval connection")
		am.cleanupTimeoutRequest(sudoApprovalReq.RequestID, false, "Service shutdown")
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

	sudoRequest.Connection.Close()

	// Signal completion to unblock the waiting goroutine
	am.signalCompletion(response.RequestID)

	log.Info().Str("request_id", response.RequestID).Bool("approved", response.Approved).Msg("SudoApprovalResponse processed successfully")
	return nil
}

func (am *AuthManager) AddPIDSessionMapping(pid int, session *SessionInfo) {
	am.mu.Lock()
	am.pidToSessionMap[pid] = session
	am.mu.Unlock()
}

func (am *AuthManager) RemovePIDSessionMapping(pid int) {
	am.mu.Lock()
	if session, exists := am.pidToSessionMap[pid]; exists {
		delete(am.pidToSessionMap, pid)
		log.Debug().Msgf("PID mapping removed: %d -> Session: %s", pid, session.SessionID)
	}
	am.mu.Unlock()
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

func (am *AuthManager) Stop() {
	if am.cancel != nil {
		am.cancel()
	}
	if am.listener != nil {
		am.listener.Close()
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
				req.Connection.Close()
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
			req.Connection.Close()
		}
		return
	}

	am.mu.Unlock()
	log.Warn().Msgf("Timeout request not found: %s", requestID)
}
