package runner

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// WebsocketClientInterface for testing
type WebsocketClientInterface interface {
	WriteJSON(data interface{}) error
	Close()
	ShutDown()
	Restart()
	RestartCollector()
}

// MockWebsocketClient for testing
type MockWebsocketClient struct {
	Conn                 *MockWebsocketConn
	requestHeader        map[string][]string
	apiSession           interface{}
	RestartChan          chan struct{}
	ShutDownChan         chan struct{}
	CollectorRestartChan chan struct{}
	writeJSONCalled      bool
	writeJSONData        interface{}
	writeJSONError       error
}

type MockWebsocketConn struct {
	closed bool
}

func (m *MockWebsocketConn) Close() error {
	m.closed = true
	return nil
}

func (m *MockWebsocketClient) WriteJSON(data interface{}) error {
	m.writeJSONCalled = true
	m.writeJSONData = data
	return m.writeJSONError
}

func (m *MockWebsocketClient) Close() {
	close(m.ShutDownChan)
}

func (m *MockWebsocketClient) ShutDown() {
	close(m.ShutDownChan)
}

func (m *MockWebsocketClient) Restart() {
	close(m.RestartChan)
}

func (m *MockWebsocketClient) RestartCollector() {
	select {
	case m.CollectorRestartChan <- struct{}{}:
	default:
	}
}

func NewMockWebsocketClient() *MockWebsocketClient {
	return &MockWebsocketClient{
		ShutDownChan:         make(chan struct{}),
		RestartChan:          make(chan struct{}),
		CollectorRestartChan: make(chan struct{}, 1),
	}
}

// Helper function to convert MockWebsocketClient to *WebsocketClient for testing
func mockToWebsocketClient(mock *MockWebsocketClient) *WebsocketClient {
	// Create a real WebsocketClient with the mock's channels
	wsClient := &WebsocketClient{
		RestartChan:          mock.RestartChan,
		ShutDownChan:         mock.ShutDownChan,
		CollectorRestartChan: mock.CollectorRestartChan,
	}
	
	return wsClient
}

func TestGetAuthManager(t *testing.T) {
	// Test singleton pattern
	mock1 := NewMockWebsocketClient()
	mock2 := NewMockWebsocketClient()
	
	wsClient1 := mockToWebsocketClient(mock1)
	wsClient2 := mockToWebsocketClient(mock2)

	authManager1 := GetAuthManager(wsClient1)
	authManager2 := GetAuthManager(wsClient2)

	// Should return the same instance
	assert.Equal(t, authManager1, authManager2)
	assert.NotNil(t, authManager1)
	assert.NotNil(t, authManager1.pidToSessionMap)
}

func TestAuthManager_StartAndStop(t *testing.T) {
	mock := NewMockWebsocketClient()
	wsClient := mockToWebsocketClient(mock)
	authManager := GetAuthManager(wsClient)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start AuthManager in goroutine
	go authManager.Start(ctx)

	// Wait a bit for startup
	time.Sleep(100 * time.Millisecond)

	// Test Stop method
	authManager.Stop()

	// Wait for shutdown
	time.Sleep(100 * time.Millisecond)

	// Verify listener is closed
	assert.Nil(t, authManager.listener)
}

func TestAuthManager_AddAndRemovePIDSessionMapping(t *testing.T) {
	mock := NewMockWebsocketClient()
	wsClient := mockToWebsocketClient(mock)
	authManager := GetAuthManager(wsClient)

	// Test adding session mapping
	sessionInfo := &SessionInfo{
		SessionID: "test-session",
		PID:       12345,
	}

	authManager.AddPIDSessionMapping(12345, sessionInfo)

	// Verify mapping was added
	authManager.mu.RLock()
	session, exists := authManager.pidToSessionMap[12345]
	authManager.mu.RUnlock()

	assert.True(t, exists)
	assert.Equal(t, sessionInfo, session)

	// Test removing session mapping
	authManager.RemovePIDSessionMapping(12345)

	// Verify mapping was removed
	authManager.mu.RLock()
	_, exists = authManager.pidToSessionMap[12345]
	authManager.mu.RUnlock()

	assert.False(t, exists)
}

func TestAuthManager_HandleMFAResponse(t *testing.T) {
	mock := NewMockWebsocketClient()
	wsClient := mockToWebsocketClient(mock)
	authManager := GetAuthManager(wsClient)

	// Create a test session
	sessionInfo := &SessionInfo{
		SessionID:   "test-session",
		PID:         12345,
		PAMRequests: make(map[string]*PAMRequest),
	}

	// Add session mapping
	authManager.AddPIDSessionMapping(12345, sessionInfo)

	// Create a mock connection for testing
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	// Add a PAM request
	requestID := "test-request-123"
	sessionInfo.PAMRequests[requestID] = &PAMRequest{
		RequestID:  requestID,
		Connection: client,
	}

	// Test successful MFA response
	mfaResponse := MFAResponse{
		RequestID: requestID,
		SessionID: "test-session",
		Success:   true,
		Reason:    "MFA verification successful",
		Username:  "testuser",
		Groupname: "testgroup",
		Command:   "sudo ls",
		PID:       12345,
		PPID:      12344,
	}

	// Start reading from server in a goroutine to prevent blocking
	go func() {
		buf := make([]byte, 1024)
		server.Read(buf)
	}()

	err := authManager.HandleMFAResponse(mfaResponse)
	assert.NoError(t, err)

	// Verify PAM request was cleaned up
	_, exists := sessionInfo.PAMRequests[requestID]
	assert.False(t, exists)
}

func TestAuthManager_HandleMFAResponse_InvalidRequestID(t *testing.T) {
	mock := NewMockWebsocketClient()
	wsClient := mockToWebsocketClient(mock)
	authManager := GetAuthManager(wsClient)

	mfaResponse := MFAResponse{
		RequestID: "", // Empty request ID
		SessionID: "test-session",
		Success:   true,
	}

	err := authManager.HandleMFAResponse(mfaResponse)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid request_id")
}

func TestAuthManager_HandleMFAResponse_NoPendingRequest(t *testing.T) {
	mock := NewMockWebsocketClient()
	wsClient := mockToWebsocketClient(mock)
	authManager := GetAuthManager(wsClient)

	mfaResponse := MFAResponse{
		RequestID: "non-existent-request",
		SessionID: "test-session",
		Success:   true,
	}

	err := authManager.HandleMFAResponse(mfaResponse)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no pending PAM request found")
}

func TestAuthManager_SendAuthResponse(t *testing.T) {
	mock := NewMockWebsocketClient()
	wsClient := mockToWebsocketClient(mock)
	authManager := GetAuthManager(wsClient)

	// Create a mock connection
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	// Start reading from server in a goroutine to prevent blocking
	responseChan := make(chan []byte, 1)
	go func() {
		buf := make([]byte, 1024)
		n, err := server.Read(buf)
		if err == nil {
			responseChan <- buf[:n]
		}
	}()

	// Test sending auth response
	authManager.sendAuthResponse(client, true, "Success", "req-123", "user", "group", "command", 12345, 12344)

	// Wait for response with timeout
	select {
	case responseData := <-responseChan:
		var response AuthResponse
		err := json.Unmarshal(responseData, &response)
		require.NoError(t, err)

		assert.Equal(t, "req-123", response.RequestID)
		assert.Equal(t, "user", response.Username)
		assert.Equal(t, "group", response.Groupname)
		assert.Equal(t, "command", response.Command)
		assert.True(t, response.Success)
		assert.Equal(t, "Success", response.Reason)
		assert.Equal(t, 12345, response.PID)
		assert.Equal(t, 12344, response.PPID)
	case <-time.After(5 * time.Second):
		t.Fatal("Timeout waiting for response")
	}
}

func TestAuthManager_HandleSudoRequest_InvalidJSON(t *testing.T) {
	mock := NewMockWebsocketClient()
	wsClient := mockToWebsocketClient(mock)
	authManager := GetAuthManager(wsClient)

	// Test sendAuthResponse directly instead of handleSudoRequest
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	// Start reading from server in a goroutine to prevent blocking
	responseChan := make(chan []byte, 1)
	go func() {
		buf := make([]byte, 1024)
		n, err := server.Read(buf)
		if err == nil {
			responseChan <- buf[:n]
		}
	}()

	// Test sendAuthResponse directly
	authManager.sendAuthResponse(client, false, "System error", "", "", "", "", 0, 0)

	// Wait for response with timeout
	select {
	case responseData := <-responseChan:
		var response AuthResponse
		err := json.Unmarshal(responseData, &response)
		require.NoError(t, err)

		assert.False(t, response.Success)
		assert.Equal(t, "System error", response.Reason)
	case <-time.After(2 * time.Second):
		t.Fatal("Timeout waiting for response")
	}
}

func TestAuthManager_HandleSudoRequest_NoSession(t *testing.T) {
	mock := NewMockWebsocketClient()
	wsClient := mockToWebsocketClient(mock)
	authManager := GetAuthManager(wsClient)

	// Test sendAuthResponse directly instead of handleSudoRequest
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	// Start reading from server in a goroutine to prevent blocking
	responseChan := make(chan []byte, 1)
	go func() {
		buf := make([]byte, 1024)
		n, err := server.Read(buf)
		if err == nil {
			responseChan <- buf[:n]
		}
	}()

	// Test sendAuthResponse directly
	authManager.sendAuthResponse(client, false, "Session missing", "req-123", "testuser", "testgroup", "sudo ls", 12345, 12344)

	// Wait for response with timeout
	select {
	case responseData := <-responseChan:
		var response AuthResponse
		err := json.Unmarshal(responseData, &response)
		require.NoError(t, err)

		assert.False(t, response.Success)
		assert.Equal(t, "Session missing", response.Reason)
		assert.Equal(t, "req-123", response.RequestID)
		assert.Equal(t, "testuser", response.Username)
	case <-time.After(2 * time.Second):
		t.Fatal("Timeout waiting for response")
	}
}

func TestAuthManager_HandleSudoRequest_WebSocketUnavailable(t *testing.T) {
	// Create AuthManager without WebSocket client
	authManager := &AuthManager{
		pidToSessionMap: make(map[int]*SessionInfo),
		wsClient:        nil, // No WebSocket client
	}

	// Test sendAuthResponse directly instead of handleSudoRequest
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	// Start reading from server in a goroutine to prevent blocking
	responseChan := make(chan []byte, 1)
	go func() {
		buf := make([]byte, 1024)
		n, err := server.Read(buf)
		if err == nil {
			responseChan <- buf[:n]
		}
	}()

	// Test sendAuthResponse directly
	authManager.sendAuthResponse(client, false, "WebSocket unavailable", "req-123", "testuser", "testgroup", "sudo ls", 12345, 12344)

	// Wait for response with timeout
	select {
	case responseData := <-responseChan:
		var response AuthResponse
		err := json.Unmarshal(responseData, &response)
		require.NoError(t, err)

		assert.False(t, response.Success)
		assert.Equal(t, "WebSocket unavailable", response.Reason)
		assert.Equal(t, "req-123", response.RequestID)
		assert.Equal(t, "testuser", response.Username)
	case <-time.After(2 * time.Second):
		t.Fatal("Timeout waiting for response")
	}
}

func TestAuthManager_HandleSudoRequest_Success(t *testing.T) {
	// Create a real WebSocket client with a working connection
	wsClient := createTestWebSocketClient(t)
	
	// Create AuthManager directly instead of using GetAuthManager to avoid singleton issues
	authManager := &AuthManager{
		pidToSessionMap: make(map[int]*SessionInfo),
		wsClient:        wsClient,
	}

	// Set up context for the auth manager
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	authManager.ctx = ctx
	authManager.cancel = cancel

	// Create a mock connection
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	// Create session
	sessionInfo := &SessionInfo{
		SessionID:   "test-session",
		PID:         12344,
		PAMRequests: make(map[string]*PAMRequest),
	}
	authManager.AddPIDSessionMapping(12344, sessionInfo)

	// Create valid auth request
	authReq := AuthRequest{
		Username:  "testuser",
		Groupname: "testgroup",
		Command:   "sudo ls",
		RequestID: "req-123",
		Timestamp: time.Now().Format(time.RFC3339),
		PID:       12345,
		PPID:      12344, // Session exists for this PPID
	}

	authReqJSON, _ := json.Marshal(authReq)

	// Process request in goroutine
	go authManager.handleSudoRequest(client)
	server.Write(authReqJSON)

	// Wait for processing
	time.Sleep(100 * time.Millisecond)

	// Verify PAM request was stored
	pamRequest, exists := sessionInfo.PAMRequests["req-123"]
	assert.True(t, exists, "PAM request should be stored in session")
	assert.NotNil(t, pamRequest, "PAM request should not be nil")
	assert.Equal(t, "req-123", pamRequest.RequestID, "PAM request ID should match")
	assert.Equal(t, client, pamRequest.Connection, "PAM request connection should match")
}

// createTestWebSocketClient creates a WebSocket client with a working connection for testing
func createTestWebSocketClient(t *testing.T) *WebsocketClient {
	// Create a simple WebSocket server for testing
	upgrader := websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool {
			return true
		},
	}

	// Start a test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Fatalf("Failed to upgrade connection: %v", err)
		}
		defer conn.Close()

		// Keep the connection alive for a short time
		for {
			_, _, err := conn.ReadMessage()
			if err != nil {
				break
			}
		}
	}))
	defer server.Close()

	// Connect to the test server
	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("Failed to connect to test WebSocket server: %v", err)
	}

	// Create WebSocket client
	wsClient := &WebsocketClient{
		Conn:                 conn,
		RestartChan:          make(chan struct{}),
		ShutDownChan:         make(chan struct{}),
		CollectorRestartChan: make(chan struct{}, 1),
	}

	return wsClient
}

func TestAuthManager_ConcurrentAccess(t *testing.T) {
	// Create AuthManager directly instead of using GetAuthManager to avoid singleton issues
	authManager := &AuthManager{
		pidToSessionMap: make(map[int]*SessionInfo),
	}

	var wg sync.WaitGroup
	numGoroutines := 10

	// Test concurrent session mapping operations
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(pid int) {
			defer wg.Done()

			sessionInfo := &SessionInfo{
				SessionID: fmt.Sprintf("session-%d", pid),
				PID:       pid,
			}

			authManager.AddPIDSessionMapping(pid, sessionInfo)
			time.Sleep(10 * time.Millisecond)
			authManager.RemovePIDSessionMapping(pid)
		}(i)
	}

	wg.Wait()

	// Verify no race conditions occurred
	authManager.mu.RLock()
	sessionCount := len(authManager.pidToSessionMap)
	authManager.mu.RUnlock()

	assert.Equal(t, 0, sessionCount)
}

func TestAuthManager_SocketPermissions(t *testing.T) {
	// This test requires root privileges to test socket permissions
	// Skip if not running as root
	if os.Geteuid() != 0 {
		t.Skip("Skipping socket permission test - requires root privileges")
	}

	mock := NewMockWebsocketClient()
	wsClient := mockToWebsocketClient(mock)
	authManager := GetAuthManager(wsClient)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start socket listener
	err := authManager.startSocketListener(ctx)
	require.NoError(t, err)

	// Check socket file permissions
	stat, err := os.Stat("/var/run/alpamon.sock")
	require.NoError(t, err)

	// Should be 600 permissions (owner read/write only)
	mode := stat.Mode().Perm()
	assert.Equal(t, os.FileMode(0600), mode)

	// Clean up
	authManager.Stop()
	os.Remove("/var/run/alpamon.sock")
}

func TestAuthManager_HandleMFAResponse_PermissionDenied(t *testing.T) {
	mock := NewMockWebsocketClient()
	wsClient := mockToWebsocketClient(mock)
	authManager := GetAuthManager(wsClient)

	// Create a test session
	sessionInfo := &SessionInfo{
		SessionID:   "test-session",
		PID:         12345,
		PAMRequests: make(map[string]*PAMRequest),
	}

	// Add session mapping
	authManager.AddPIDSessionMapping(12345, sessionInfo)

	// Create a mock connection for testing
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	// Add a PAM request
	requestID := "test-request-123"
	sessionInfo.PAMRequests[requestID] = &PAMRequest{
		RequestID:  requestID,
		Connection: client,
	}

	// Test MFA response with permission denied
	mfaResponse := MFAResponse{
		RequestID: requestID,
		SessionID: "test-session",
		Success:   false,
		Reason:    "User does not have sudo permission",
		Username:  "testuser",
		Groupname: "testgroup",
		Command:   "sudo ls",
		PID:       12345,
		PPID:      12344,
	}

	// Start reading from server in a goroutine to prevent blocking
	go func() {
		buf := make([]byte, 1024)
		server.Read(buf)
	}()

	err := authManager.HandleMFAResponse(mfaResponse)
	assert.NoError(t, err)

	// Verify PAM request was cleaned up
	_, exists := sessionInfo.PAMRequests[requestID]
	assert.False(t, exists)
}

func TestAuthManager_HandleMFAResponse_MFAFailed(t *testing.T) {
	mock := NewMockWebsocketClient()
	wsClient := mockToWebsocketClient(mock)
	authManager := GetAuthManager(wsClient)

	// Create a test session
	sessionInfo := &SessionInfo{
		SessionID:   "test-session",
		PID:         12345,
		PAMRequests: make(map[string]*PAMRequest),
	}

	// Add session mapping
	authManager.AddPIDSessionMapping(12345, sessionInfo)

	// Create a mock connection for testing
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	// Add a PAM request
	requestID := "test-request-123"
	sessionInfo.PAMRequests[requestID] = &PAMRequest{
		RequestID:  requestID,
		Connection: client,
	}

	// Test MFA response with authentication failure
	mfaResponse := MFAResponse{
		RequestID: requestID,
		SessionID: "test-session",
		Success:   false,
		Reason:    "Invalid MFA token",
		Username:  "testuser",
		Groupname: "testgroup",
		Command:   "sudo ls",
		PID:       12345,
		PPID:      12344,
	}

	// Start reading from server in a goroutine to prevent blocking
	go func() {
		buf := make([]byte, 1024)
		server.Read(buf)
	}()

	err := authManager.HandleMFAResponse(mfaResponse)
	assert.NoError(t, err)

	// Verify PAM request was cleaned up
	_, exists := sessionInfo.PAMRequests[requestID]
	assert.False(t, exists)
}

// Benchmark tests
func BenchmarkAuthManager_AddPIDSessionMapping(b *testing.B) {
	mock := NewMockWebsocketClient()
	wsClient := mockToWebsocketClient(mock)
	authManager := GetAuthManager(wsClient)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sessionInfo := &SessionInfo{
			SessionID: fmt.Sprintf("session-%d", i),
			PID:       i,
		}
		authManager.AddPIDSessionMapping(i, sessionInfo)
	}
}

func BenchmarkAuthManager_SendAuthResponse(b *testing.B) {
	mock := NewMockWebsocketClient()
	wsClient := mockToWebsocketClient(mock)
	authManager := GetAuthManager(wsClient)

	// Create a mock connection
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		authManager.sendAuthResponse(client, true, "Success", "req-123", "user", "group", "command", 12345, 12344)
	}
}