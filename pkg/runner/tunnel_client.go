package runner

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/alpacax/alpamon/pkg/config"
	"github.com/alpacax/alpamon/pkg/tunnel"
	"github.com/gorilla/websocket"
	"github.com/rs/zerolog/log"
	"github.com/xtaci/smux"
)

// maxMetadataSize is the maximum size of stream metadata to prevent DoS attacks.
const maxMetadataSize = 1024

// Client type constants for tunnel connections
const (
	ClientTypeCLI    = "cli"
	ClientTypeWeb    = "web"
	ClientTypeEditor = "editor"
)

// activeTunnels tracks all active tunnel connections by session ID.
var (
	activeTunnels   = make(map[string]*TunnelClient)
	activeTunnelsMu sync.RWMutex
)

// streamMetadata contains the target port information sent by the server.
type streamMetadata struct {
	RemotePort  string `json:"remote_port"`
	HealthCheck bool   `json:"health_check,omitempty"`
}

// TunnelClient manages the smux-multiplexed tunnel connection to the proxy server.
// It accepts streams from the server and relays them to local services.
type TunnelClient struct {
	sessionID     string
	clientType    string // cli, web, editor
	targetPort    int    // for cli/web type
	username      string // for editor type
	groupname     string // for editor type
	serverURL     string
	requestHeader http.Header
	wsConn        *websocket.Conn
	session       *smux.Session
	ctx           context.Context
	cancel        context.CancelFunc
	codeServerMgr *CodeServerManager // for editor type
}

// NewTunnelClient creates a new tunnel client for the given WebSocket URL.
func NewTunnelClient(sessionID, clientType string, targetPort int, username, groupname, url string) *TunnelClient {
	headers := http.Header{
		"Authorization": {fmt.Sprintf(`id="%s", key="%s"`, config.GlobalSettings.ID, config.GlobalSettings.Key)},
		"Origin":        {config.GlobalSettings.ServerURL},
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &TunnelClient{
		sessionID:     sessionID,
		clientType:    clientType,
		targetPort:    targetPort,
		username:      username,
		groupname:     groupname,
		serverURL:     url,
		requestHeader: headers,
		ctx:           ctx,
		cancel:        cancel,
	}
}

// RunTunnelBackground starts the tunnel connection in a goroutine.
func (tc *TunnelClient) RunTunnelBackground() {
	// Register in active tunnels
	activeTunnelsMu.Lock()
	activeTunnels[tc.sessionID] = tc
	activeTunnelsMu.Unlock()

	defer func() {
		// Cleanup on exit
		activeTunnelsMu.Lock()
		delete(activeTunnels, tc.sessionID)
		activeTunnelsMu.Unlock()
		tc.Close()
	}()

	// For editor type, initialize code-server manager (startup triggered by health_check)
	if tc.clientType == ClientTypeEditor {
		if err := tc.initCodeServerManager(); err != nil {
			log.Error().Err(err).Msgf("Failed to initialize code-server manager for session %s.", tc.sessionID)
			return
		}
	}

	// Connect and run
	if err := tc.connect(); err != nil {
		log.Error().Err(err).Msgf("Tunnel connection failed for session %s.", tc.sessionID)
		return
	}

	log.Info().Msgf("Tunnel connection established for session %s, target port %d.", tc.sessionID, tc.targetPort)
	tc.handleStreams()
	log.Info().Msgf("Tunnel session %s ended.", tc.sessionID)
}

// initCodeServerManager creates the code-server manager without starting it.
// The actual startup is triggered by health_check requests.
func (tc *TunnelClient) initCodeServerManager() error {
	mgr, err := NewCodeServerManager(tc.ctx, tc.username, tc.groupname)
	if err != nil {
		return fmt.Errorf("failed to create code-server manager: %w", err)
	}
	tc.codeServerMgr = mgr
	log.Info().Msgf("code-server manager initialized for session %s (user: %s).", tc.sessionID, tc.username)
	return nil
}

// handleHealthCheck responds to health check requests with code-server status.
func (tc *TunnelClient) handleHealthCheck(stream *smux.Stream) {
	if tc.codeServerMgr == nil {
		tc.sendHealthResponse(stream, "error", "code-server manager not initialized")
		return
	}

	status, lastError := tc.codeServerMgr.Status()

	if status == CodeServerStatusIdle {
		tc.codeServerMgr.StartAsync()
		status, _ = tc.codeServerMgr.Status()
	}

	if status == CodeServerStatusReady {
		tc.targetPort = tc.codeServerMgr.Port()
	}

	tc.sendHealthResponse(stream, string(status), lastError)
}

// sendHealthResponse sends an HTTP response with health status.
func (tc *TunnelClient) sendHealthResponse(stream *smux.Stream, status, errMsg string) {
	httpStatus := getHTTPStatusForHealth(status)
	body := buildHealthResponseBody(status, errMsg)

	response := fmt.Sprintf("HTTP/1.1 %d %s\r\n"+
		"Content-Type: application/json\r\n"+
		"Content-Length: %d\r\n"+
		"Connection: close\r\n"+
		"\r\n%s",
		httpStatus, http.StatusText(httpStatus), len(body), body)

	if _, err := stream.Write([]byte(response)); err != nil {
		log.Debug().Err(err).Msg("Failed to write health response")
	}
}

func getHTTPStatusForHealth(status string) int {
	switch status {
	case "ready":
		return http.StatusOK
	case "installing", "starting":
		return http.StatusServiceUnavailable
	default:
		return http.StatusInternalServerError
	}
}

func buildHealthResponseBody(status, errMsg string) string {
	if errMsg != "" {
		return fmt.Sprintf(`{"status":"%s","error":"%s"}`, status, errMsg)
	}
	return fmt.Sprintf(`{"status":"%s"}`, status)
}

// connect establishes WebSocket connection and creates smux session.
func (tc *TunnelClient) connect() error {
	log.Info().Msgf("Connecting to tunnel server at %s...", tc.serverURL)

	dialer := websocket.Dialer{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: !config.GlobalSettings.SSLVerify,
		},
		HandshakeTimeout: 30 * time.Second,
	}

	// Server URL is provided by the authenticated Alpacon console which the agent trusts.
	conn, _, err := dialer.Dial(tc.serverURL, tc.requestHeader) // lgtm[go/request-forgery]
	if err != nil {
		return fmt.Errorf("failed to connect to tunnel server: %w", err)
	}

	tc.wsConn = conn

	// Create smux client session over WebSocket
	wsNetConn := tunnel.NewWebSocketConn(tc.wsConn)
	session, err := smux.Client(wsNetConn, config.GetSmuxConfig())
	if err != nil {
		_ = tc.wsConn.Close()
		return fmt.Errorf("failed to create smux session: %w", err)
	}

	tc.session = session
	log.Debug().Msgf("Tunnel smux session established for %s.", tc.sessionID)
	return nil
}

// handleStreams accepts and processes incoming smux streams from the server.
func (tc *TunnelClient) handleStreams() {
	for {
		stream, err := tc.session.AcceptStream()

		if err != nil {
			select {
			case <-tc.ctx.Done():
				return
			default:
				log.Debug().Err(err).Msgf("Tunnel session %s closed.", tc.sessionID)
				return
			}
		}
		go tc.handleStream(stream)
	}
}

// handleStream processes a single smux stream by spawning a worker subprocess
// with user credentials to connect to the local service.
func (tc *TunnelClient) handleStream(stream *smux.Stream) {
	defer func() { _ = stream.Close() }()

	metadata, bufReader, err := tc.readStreamMetadata(stream)
	if err != nil {
		log.Debug().Err(err).Msg("Failed to read stream metadata.")
		return
	}

	log.Info().
		Str("remote_port", metadata.RemotePort).
		Bool("health_check", metadata.HealthCheck).
		Msg("Received stream metadata")

	if metadata.HealthCheck && tc.clientType == ClientTypeEditor {
		tc.handleHealthCheck(stream)
		return
	}

	targetPort, err := tc.resolveTargetPort(metadata.RemotePort)
	if err != nil {
		log.Debug().Err(err).Msg("Invalid target port.")
		return
	}

	targetAddr := fmt.Sprintf("127.0.0.1:%d", targetPort)

	// Spawn tunnel worker subprocess (runs as nobody user for security)
	cmd, stdinPipe, stdoutPipe, err := spawnTunnelWorker(targetAddr)
	if err != nil {
		log.Debug().Err(err).Msgf("Failed to spawn tunnel worker for %s.", targetAddr)
		return
	}

	defer func() {
		_ = stdinPipe.Close()
		if cmd.Process != nil {
			if err := cmd.Process.Kill(); err != nil {
				if !errors.Is(err, os.ErrProcessDone) {
					log.Debug().Err(err).Msg("Failed to kill tunnel worker process.")
				}
			}
		}
		if err := cmd.Wait(); err != nil {
		log.Debug().Err(err).Msg("Tunnel worker process exited with error.")
	}
	}()

	log.Debug().Msgf("Tunnel worker spawned for %s.", targetAddr)

	dataReader := tc.buildDataReader(bufReader, stream)
	tc.relayBidirectional(stream, stdinPipe, stdoutPipe, dataReader)

	log.Debug().Msgf("Tunnel stream closed for port %d.", targetPort)
}

func (tc *TunnelClient) readStreamMetadata(stream *smux.Stream) (*streamMetadata, *bufio.Reader, error) {
	limitedReader := &io.LimitedReader{R: stream, N: maxMetadataSize}
	bufReader := bufio.NewReader(limitedReader)

	metadataLine, err := bufReader.ReadString('\n')
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read metadata: %w", err)
	}

	var metadata streamMetadata
	if err := json.Unmarshal([]byte(metadataLine), &metadata); err != nil {
		return nil, nil, fmt.Errorf("failed to parse metadata: %w", err)
	}

	return &metadata, bufReader, nil
}

func (tc *TunnelClient) resolveTargetPort(remotePort string) (int, error) {
	if remotePort == "" {
		return tc.targetPort, nil
	}

	port, err := strconv.Atoi(remotePort)
	if err != nil || port < 1 || port > 65535 {
		return 0, fmt.Errorf("invalid port: %s", remotePort)
	}
	return port, nil
}

func (tc *TunnelClient) buildDataReader(bufReader *bufio.Reader, stream *smux.Stream) io.Reader {
	bufferedSize := bufReader.Buffered()
	if bufferedSize == 0 {
		return stream
	}

	remainingBuf := make([]byte, bufferedSize)
	n, err := io.ReadFull(bufReader, remainingBuf)
	if err != nil && err != io.EOF {
		log.Debug().Err(err).Msg("Failed to read remaining buffered data.")
		return stream
	}

	return io.MultiReader(bytes.NewReader(remainingBuf[:n]), stream)
}

func (tc *TunnelClient) relayBidirectional(stream *smux.Stream, stdinPipe io.WriteCloser, stdoutPipe io.ReadCloser, dataReader io.Reader) {
	errChan := make(chan error, 2)

	go func() {
		_, err := io.Copy(stdinPipe, dataReader)
		_ = stdinPipe.Close()
		errChan <- err
	}()

	go func() {
		_, err := tunnel.CopyBuffered(stream, stdoutPipe)
		errChan <- err
	}()

	<-errChan
}

// Close cleanly shuts down the tunnel connection.
func (tc *TunnelClient) Close() {
	// Stop code-server first (for editor type)
	if tc.codeServerMgr != nil {
		if err := tc.codeServerMgr.Stop(); err != nil {
			log.Debug().Err(err).Msg("Failed to stop code-server.")
		}
		tc.codeServerMgr = nil
	}

	if tc.cancel != nil {
		tc.cancel()
	}
	if tc.session != nil {
		_ = tc.session.Close()
	}
	if tc.wsConn != nil {
		_ = tc.wsConn.WriteControl(
			websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""),
			time.Now().Add(5*time.Second),
		)
		_ = tc.wsConn.Close()
	}
}

// CloseTunnel closes an active tunnel by session ID.
func CloseTunnel(sessionID string) error {
	activeTunnelsMu.Lock()
	tc, exists := activeTunnels[sessionID]
	if !exists {
		activeTunnelsMu.Unlock()
		return fmt.Errorf("tunnel session %s not found", sessionID)
	}
	// Remove from active tunnels under lock to prevent race condition with defer cleanup
	delete(activeTunnels, sessionID)
	activeTunnelsMu.Unlock()

	tc.Close()
	return nil
}

// GetActiveTunnel returns an active tunnel by session ID.
func GetActiveTunnel(sessionID string) (*TunnelClient, bool) {
	activeTunnelsMu.RLock()
	defer activeTunnelsMu.RUnlock()
	tc, exists := activeTunnels[sessionID]
	return tc, exists
}
