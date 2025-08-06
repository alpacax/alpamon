package runner

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

type SessionInfo struct {
	SessionID   string
	PID         int
	PtyClient   *PtyClient
	PAMRequests map[string]*PAMRequest
}

type PAMRequest struct {
	RequestID  string
	Connection net.Conn
}

type AuthRequest struct {
	Username  string `json:"username"`
	Groupname string `json:"groupname"`
	Command   string `json:"command"`
	RequestID string `json:"request_id"`
	Timestamp string `json:"timestamp"`
	PID       int    `json:"pid"`
	PPID      int    `json:"ppid"`
}

type AuthResponse struct {
	RequestID string `json:"request_id"`
	Username  string `json:"username"`
	Groupname string `json:"groupname"`
	Command   string `json:"command"`
	Timestamp string `json:"timestamp"`
	Success   bool   `json:"success"`
	Reason    string `json:"reason"`
	PID       int    `json:"pid"`
	PPID      int    `json:"ppid"`
}

type MFARequest struct {
	Type      string `json:"type"`
	Query     string `json:"query"`
	RequestID string `json:"request_id"`
	Username  string `json:"username"`
	Groupname string `json:"groupname"`
	Command   string `json:"command"`
	SessionID string `json:"session_id"`
	Timestamp string `json:"timestamp"`
	PID       int    `json:"pid"`
	PPID      int    `json:"ppid"`
}

type MFAResponse struct {
	Type      string `json:"type"`
	Query     string `json:"query"`
	RequestID string `json:"request_id"`
	Username  string `json:"username"`
	Groupname string `json:"groupname"`
	Command   string `json:"command"`
	SessionID string `json:"session_id"`
	Timestamp string `json:"timestamp"`
	Success   bool   `json:"success"`
	Reason    string `json:"reason"`
	PID       int    `json:"pid"`
	PPID      int    `json:"ppid"`
}

type AuthManager struct {
	mu              sync.RWMutex
	ctx             context.Context
	cancel          context.CancelFunc
	pidToSessionMap map[int]*SessionInfo
	wsClient        *WebsocketClient
	listener        net.Listener
}

var (
	authManager     *AuthManager
	authManagerOnce sync.Once
)

func GetAuthManager(wsClient *WebsocketClient) *AuthManager {
	authManagerOnce.Do(func() {
		authManager = &AuthManager{
			pidToSessionMap: make(map[int]*SessionInfo),
		}
	})

	if authManager.wsClient == nil {
		authManager.wsClient = wsClient
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
	const socketPath = "/var/run/alpamon.sock"

	if err := os.MkdirAll("/var/run", 0777); err != nil {
		return fmt.Errorf("failed to create socket directory: %w", err)
	}

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
			unix_conn, err := am.listener.Accept()
			if err != nil {
				if ctx.Err() != nil {
					return nil
				}
				log.Warn().Err(err).Msg("Socket accept error")
				continue
			}

			go am.handleSudoRequest(unix_conn)
		}
	}
}

func (am *AuthManager) handleSudoRequest(unix_conn net.Conn) {
	defer func() {
		unix_conn.Close()
		log.Debug().Msg("Unix connection closed")
	}()

	buf := make([]byte, 1024)
	n, err := unix_conn.Read(buf)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to read sudo request")
		am.sendAuthResponse(unix_conn, false, "System error", "", "", "", "", 0, 0)
		return
	}

	var authReq AuthRequest
	if err := json.Unmarshal(buf[:n], &authReq); err != nil {
		log.Warn().Err(err).Msg("Invalid PAM JSON request")
		am.sendAuthResponse(unix_conn, false, "System error", authReq.RequestID, authReq.Username, authReq.Groupname, authReq.Command, authReq.PID, authReq.PPID)
		return
	}

	am.mu.RLock()
	session, exists := am.pidToSessionMap[authReq.PPID]
	am.mu.RUnlock()

	if !exists {
		log.Warn().Msgf("No session found for PID %d", authReq.PPID)
		am.sendAuthResponse(unix_conn, false, "Session missing", authReq.RequestID, authReq.Username, authReq.Groupname, authReq.Command, authReq.PID, authReq.PPID)
		return
	}

	requestID := authReq.RequestID
	req := MFARequest{
		Type:      "auth",
		Query:     "mfa_request",
		RequestID: requestID,
		Username:  authReq.Username,
		Groupname: authReq.Groupname,
		Command:   authReq.Command,
		SessionID: session.SessionID,
		Timestamp: authReq.Timestamp,
		PID:       authReq.PID,
		PPID:      authReq.PPID,
	}

	if am.wsClient == nil || am.wsClient.Conn == nil {
		log.Error().Msg("WebSocket client not available")
		am.sendAuthResponse(unix_conn, false, "WebSocket unavailable", authReq.RequestID, authReq.Username, authReq.Groupname, authReq.Command, authReq.PID, authReq.PPID)
		return
	}

	if err := am.wsClient.WriteJSON(req); err != nil {
		log.Error().Err(err).Msg("Failed to send MFA request to WebSocket client")
		am.sendAuthResponse(unix_conn, false, "System error", authReq.RequestID, authReq.Username, authReq.Groupname, authReq.Command, authReq.PID, authReq.PPID)
		return
	}

	am.mu.Lock()
	if session, exists := am.pidToSessionMap[authReq.PPID]; exists {
		if session.PAMRequests == nil {
			session.PAMRequests = make(map[string]*PAMRequest)
		}
		session.PAMRequests[requestID] = &PAMRequest{
			RequestID:  requestID,
			Connection: unix_conn,
		}
	}
	am.mu.Unlock()

	select {
	case <-time.After(30 * time.Second):
		log.Warn().Msg("MFA response timeout")
		am.sendAuthResponse(unix_conn, false, "Response timeout", authReq.RequestID, authReq.Username, authReq.Groupname, authReq.Command, authReq.PID, authReq.PPID)
	case <-am.ctx.Done():
		am.sendAuthResponse(unix_conn, false, "System error", authReq.RequestID, authReq.Username, authReq.Groupname, authReq.Command, authReq.PID, authReq.PPID)
	}

	am.mu.Lock()
	if session, exists := am.pidToSessionMap[authReq.PPID]; exists {
		delete(session.PAMRequests, requestID)
	}
	am.mu.Unlock()
}

func (am *AuthManager) sendAuthResponse(conn net.Conn, success bool, reason, requestID, username, groupname, command string, pid, ppid int) {
	authResponse := AuthResponse{
		RequestID: requestID,
		Username:  username,
		Groupname: groupname,
		Command:   command,
		Timestamp: time.Now().Format(time.RFC3339),
		Success:   success,
		Reason:    reason,
		PID:       pid,
		PPID:      ppid,
	}

	responseJSON, err := json.Marshal(authResponse)
	if err != nil {
		log.Error().Err(err).Msg("Failed to marshal auth response")
		return
	}

	_, err = conn.Write(responseJSON)
	if err != nil {
		log.Error().Err(err).Msg("Failed to send auth response")
		return
	}
}

func (am *AuthManager) HandleMFAResponse(mfaResponse MFAResponse) error {
	requestID := mfaResponse.RequestID
	if requestID == "" {
		return fmt.Errorf("invalid request_id in MFA response")
	}

	log.Info().Str("request_id", requestID).Str("session_id", mfaResponse.SessionID).Msg("Processing MFA response")

	am.mu.Lock()
	var targetSession *SessionInfo
	var pamRequest *PAMRequest

	for _, session := range am.pidToSessionMap {
		if session.SessionID == mfaResponse.SessionID {
			if pamReq, exists := session.PAMRequests[requestID]; exists {
				targetSession = session
				pamRequest = pamReq
				break
			}
		}
	}
	am.mu.Unlock()

	if pamRequest == nil {
		return fmt.Errorf("no pending PAM request found for request_id: %s, session_id: %s", requestID, mfaResponse.SessionID)
	}

	// Send response using unified function
	am.sendAuthResponse(
		pamRequest.Connection,
		mfaResponse.Success,
		mfaResponse.Reason,
		mfaResponse.RequestID,
		mfaResponse.Username,
		mfaResponse.Groupname,
		mfaResponse.Command,
		mfaResponse.PID,
		mfaResponse.PPID,
	)

	am.mu.Lock()
	if targetSession != nil {
		delete(targetSession.PAMRequests, requestID)
	}
	am.mu.Unlock()

	pamRequest.Connection.Close()

	log.Info().Str("request_id", requestID).Bool("success", mfaResponse.Success).Msg("AuthResponse processed successfully")
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

func (am *AuthManager) Stop() {
	if am.cancel != nil {
		am.cancel()
	}
	if am.listener != nil {
		am.listener.Close()
	}
	// Log message is already printed in Start() method when context is cancelled
}
