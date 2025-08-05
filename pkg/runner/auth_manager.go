package runner

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	//"github.com/gorilla/websocket"
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

	if err := os.Chmod(socketPath, 0777); err != nil {
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
				log.Warn().Err(err).Msg("Socket accept error")
				continue
			}

			go am.handleSudoRequest(unix_conn)
		}
	}
}

func (am *AuthManager) handleSudoRequest(unix_conn net.Conn) {
	defer unix_conn.Close()

	buf := make([]byte, 1024)
	n, err := unix_conn.Read(buf)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to read sudo request")
		return
	}
	fmt.Println("buf: ", string(buf[:n]))
	
	var authReq AuthRequest
	if err := json.Unmarshal(buf[:n], &authReq); err != nil {
		log.Warn().Err(err).Msg("Invalid PAM JSON request")
		unix_conn.Write([]byte("mfa_failed"))
		return
	}
	fmt.Println("authReq: ", authReq)

	am.mu.RLock()
	session, exists := am.pidToSessionMap[authReq.PPID]
	am.mu.RUnlock()

	if !exists {
		log.Warn().Msgf("No session found for PID %d", authReq.PPID)
		unix_conn.Write([]byte("mfa_failed"))
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
		unix_conn.Write([]byte("mfa_failed"))
		return
	}

	if err := am.wsClient.WriteJSON(req); err != nil {
		log.Error().Err(err).Msg("Failed to send MFA request to WebSocket client")
		unix_conn.Write([]byte("mfa_failed"))
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
		unix_conn.Write([]byte("mfa_timeout"))
	case <-am.ctx.Done():
		unix_conn.Write([]byte("mfa_failed"))
	}

	am.mu.Lock()
	if session, exists := am.pidToSessionMap[authReq.PID]; exists {
		delete(session.PAMRequests, requestID)
	}
	am.mu.Unlock()
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

	responseJSON, err := json.Marshal(mfaResponse)
	if err != nil {
		log.Error().Err(err).Str("request_id", requestID).Msg("Failed to marshal MFA response to JSON")
		return err
	}

	_, err = pamRequest.Connection.Write(responseJSON)
	if err != nil {
		log.Error().Err(err).Str("request_id", requestID).Str("session_id", mfaResponse.SessionID).Msg("Failed to send MFA response to PAM")
		return err
	}

	am.mu.Lock()
	if targetSession != nil {
		delete(targetSession.PAMRequests, requestID)
	}
	am.mu.Unlock()

	pamRequest.Connection.Close()

	log.Info().Str("request_id", requestID).Bool("success", mfaResponse.Success).Msg("MFA response processed successfully")
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
