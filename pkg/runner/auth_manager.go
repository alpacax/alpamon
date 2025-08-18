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
	IsAlpconUser bool   `json:"is_alpcon_user"`
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
	IsAlpconUser bool   `json:"is_alpcon_user"`
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
	IsAlpconUser bool   `json:"is_alpcon_user"`
	Success      bool   `json:"success"`
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
	IsAlpconUser bool   `json:"is_alpcon_user"`
}

type AuthManager struct {
	mu                sync.RWMutex
	ctx               context.Context
	cancel            context.CancelFunc
	pidToSessionMap   map[int]*SessionInfo
	wsClient          *WebsocketClient
	listener          net.Listener
	localSudoRequests map[string]*SudoRequest
}

var (
	authManager     *AuthManager
	authManagerOnce sync.Once
)

func GetAuthManager(wsClient *WebsocketClient) *AuthManager {
	authManagerOnce.Do(func() {
		authManager = &AuthManager{
			pidToSessionMap:   make(map[int]*SessionInfo),
			localSudoRequests: make(map[string]*SudoRequest),
		}
	})

	if authManager.wsClient == nil {
		authManager.wsClient = wsClient
	}

	if authManager.localSudoRequests == nil {
		authManager.localSudoRequests = make(map[string]*SudoRequest)
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
		am.sendIsAlpconResponse(unix_conn, "", "", 0, 0, false)
		return
	}

	var requestData map[string]interface{}
	if err := json.Unmarshal(buf[:n], &requestData); err != nil {
		log.Warn().Err(err).Msg("Invalid JSON request")
		unix_conn.Close()
		return
	}

	requestType, ok := requestData["type"].(string)
	if !ok {
		log.Warn().Msg("Missing or invalid type field")
		unix_conn.Close()
		return
	}

	switch requestType {
	case "check_user":
		var isAlpconReq IsAlpconRequest
		if err := json.Unmarshal(buf[:n], &isAlpconReq); err != nil {
			log.Warn().Err(err).Msg("Invalid is_alpcon_request")
			am.sendIsAlpconResponse(unix_conn, "", "", 0, 0, false)
			return
		}

		am.mu.RLock()
		session, exists := am.pidToSessionMap[isAlpconReq.PPID]
		am.mu.RUnlock()

		if !exists {
			log.Warn().Msgf("No session found for PID %d, username: %s, groupname: %s", isAlpconReq.PPID, isAlpconReq.Username, isAlpconReq.Groupname)
			am.sendIsAlpconResponse(unix_conn, isAlpconReq.Username, isAlpconReq.Groupname, isAlpconReq.PID, isAlpconReq.PPID, false)
			return
		}

		log.Debug().Msgf("Session found for PID %d: %s", isAlpconReq.PPID, session.SessionID)
		am.sendIsAlpconResponse(unix_conn, isAlpconReq.Username, isAlpconReq.Groupname, isAlpconReq.PID, isAlpconReq.PPID, true)

	case "sudo_approval":
		var sudo_approval_req SudoApprovalRequest
		if err := json.Unmarshal(buf[:n], &sudo_approval_req); err != nil {
			log.Warn().Err(err).Msg("Invalid sudo_approval_request")
			am.sendSudoApprovalResponse(unix_conn, sudo_approval_req, false, "Invalid sudo_approval_request")
			return
		}

		am.mu.RLock()
		session, exists := am.pidToSessionMap[sudo_approval_req.PPID]
		am.mu.RUnlock()

		if !exists {
			// local user: save in localSudoRequests
			sudo_approval_req.IsAlpconUser = false
			sudo_approval_req.SessionID = ""

			am.mu.Lock()
			am.localSudoRequests[sudo_approval_req.RequestID] = &SudoRequest{
				RequestID:  sudo_approval_req.RequestID,
				Connection: unix_conn,
			}
			am.mu.Unlock()

			log.Debug().Msgf("Local user sudo request: %s for user %s", sudo_approval_req.RequestID, sudo_approval_req.Username)
		} else {
			// Alpacon user: pidToSessionMap
			sudo_approval_req.IsAlpconUser = true
			sudo_approval_req.SessionID = session.SessionID

			am.mu.Lock()
			session.Requests[sudo_approval_req.RequestID] = &SudoRequest{
				RequestID:  sudo_approval_req.RequestID,
				Connection: unix_conn,
			}
			am.mu.Unlock()

			log.Debug().Msgf("Alpacon user sudo request: %s for session %s", sudo_approval_req.RequestID, session.SessionID)
		}

		if am.wsClient == nil || am.wsClient.Conn == nil {
			log.Error().Msg("WebSocket client not available")
			am.sendSudoApprovalResponse(unix_conn, sudo_approval_req, false, "WebSocket unavailable")
			return
		}

		// Send Sudo Approval request to the alpacon-server
		if err := am.wsClient.WriteJSON(sudo_approval_req); err != nil {
			log.Error().Err(err).Msg("Failed to send sudo_approval request to WebSocket client")
			am.sendSudoApprovalResponse(unix_conn, sudo_approval_req, false, "System error")
			return
		}

		log.Debug().Msgf("sudo_approval request sent to WebSocket client, waiting for response...")

		// timeout: should make responseChannel to checkif sudo approval request is processed already
		select {
		case <-time.After(30 * time.Second):
			log.Warn().Msg("sudo_approval response timeout")
			am.cleanupTimeoutRequest(sudo_approval_req.RequestID, false, "Response timeout")
		case <-am.ctx.Done():
			log.Debug().Msg("Context cancelled, closing sudo_approval connection")
			return
		}
	}
}

func (am *AuthManager) sendIsAlpconResponse(conn net.Conn, username, groupname string, pid, ppid int, isAlpconUser bool) {
	response := IsAlpconResponse{
		Type:         "is_alpcon_response",
		Username:     username,
		Groupname:    groupname,
		PID:          pid,
		PPID:         ppid,
		IsAlpconUser: isAlpconUser,
	}

	responseJSON, err := json.Marshal(response)
	if err != nil {
		log.Error().Err(err).Msg("Failed to marshal is_alpcon_response")
		return
	}

	_, err = conn.Write(responseJSON)
	if err != nil {
		log.Error().Err(err).Msg("Failed to send is_alpcon_response")
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
			am.mu.Unlock()
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
		am.mu.Unlock()
	}

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
		log.Error().Err(err).Msg("Failed to send sudo_approval_response")
		return err
	}

	sudoRequest.Connection.Close()

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
		}
		return
	}

	am.mu.Unlock()
	log.Warn().Msgf("Timeout request not found: %s", requestID)
}
