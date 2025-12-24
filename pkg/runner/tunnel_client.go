package runner

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/alpacax/alpamon/pkg/config"
	"github.com/alpacax/alpamon/pkg/tunnel"
	"github.com/gorilla/websocket"
	"github.com/rs/zerolog/log"
	"github.com/xtaci/smux"
)

// activeTunnels tracks all active tunnel connections by session ID.
var (
	activeTunnels   = make(map[string]*TunnelClient)
	activeTunnelsMu sync.RWMutex
)

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

	// For editor type, start code-server first
	if tc.clientType == "editor" {
		if err := tc.startCodeServer(); err != nil {
			log.Error().Err(err).Msgf("Failed to start code-server for session %s.", tc.sessionID)
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

// startCodeServer initializes and starts code-server for editor tunneling.
func (tc *TunnelClient) startCodeServer() error {
	mgr, err := NewCodeServerManager(tc.username, tc.groupname)
	if err != nil {
		return fmt.Errorf("failed to create code-server manager: %w", err)
	}

	if err := mgr.Start(); err != nil {
		return fmt.Errorf("failed to start code-server: %w", err)
	}

	tc.codeServerMgr = mgr
	tc.targetPort = mgr.Port()

	log.Info().
		Int("port", tc.targetPort).
		Str("user", tc.username).
		Str("session", tc.sessionID).
		Msg("code-server ready for tunneling.")

	return nil
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

	conn, _, err := dialer.Dial(tc.serverURL, tc.requestHeader)
	if err != nil {
		return fmt.Errorf("failed to connect to tunnel server: %w", err)
	}

	tc.wsConn = conn

	// Create smux client session over WebSocket
	wsNetConn := tunnel.NewWebSocketConn(tc.wsConn)
	session, err := smux.Client(wsNetConn, config.GetSmuxConfig())
	if err != nil {
		tc.wsConn.Close()
		return fmt.Errorf("failed to create smux session: %w", err)
	}

	tc.session = session
	log.Debug().Msgf("Tunnel smux session established for %s.", tc.sessionID)
	return nil
}

// handleStreams accepts and processes incoming smux streams from the server.
func (tc *TunnelClient) handleStreams() {
	for {
		select {
		case <-tc.ctx.Done():
			return
		default:
			stream, err := tc.session.AcceptStream()
			if err != nil {
				log.Debug().Err(err).Msgf("Tunnel session %s closed.", tc.sessionID)
				return
			}

			go tc.handleStream(stream)
		}
	}
}

// streamMetadata contains the target port information sent by the server.
type streamMetadata struct {
	RemotePort string `json:"remote_port"`
}

// maxMetadataSize is the maximum size of stream metadata to prevent DoS attacks.
const maxMetadataSize = 1024

// handleStream processes a single smux stream by spawning a worker subprocess
// with user credentials to connect to the local service.
func (tc *TunnelClient) handleStream(stream *smux.Stream) {
	defer stream.Close()

	// Read metadata with size limit to prevent memory exhaustion from malicious servers
	limitedReader := &io.LimitedReader{R: stream, N: maxMetadataSize}
	bufReader := bufio.NewReader(limitedReader)
	metadataLine, err := bufReader.ReadString('\n')
	if err != nil {
		log.Debug().Err(err).Msg("Failed to read stream metadata (may exceed size limit).")
		return
	}

	var metadata streamMetadata
	if err := json.Unmarshal([]byte(metadataLine), &metadata); err != nil {
		log.Debug().Err(err).Msg("Failed to parse stream metadata.")
		return
	}

	// Use target port from tunnel configuration if not specified in metadata
	targetPort := metadata.RemotePort
	if targetPort == "" {
		targetPort = fmt.Sprintf("%d", tc.targetPort)
	}

	targetAddr := fmt.Sprintf("127.0.0.1:%s", targetPort)

	// Spawn tunnel worker subprocess (runs as nobody user for security)
	cmd, stdinPipe, stdoutPipe, err := spawnTunnelWorker(targetAddr)
	if err != nil {
		log.Debug().Err(err).Msgf("Failed to spawn tunnel worker for %s.", targetAddr)
		return
	}

	defer func() {
		stdinPipe.Close()
		if cmd.Process != nil {
			if err := cmd.Process.Kill(); err != nil {
				log.Debug().Err(err).Msg("Failed to kill tunnel worker process.")
			}
		}
		_ = cmd.Wait()
	}()

	log.Debug().Msgf("Tunnel worker spawned for %s.", targetAddr)

	// Create combined reader: remaining buffered data + original stream
	// This is needed because bufReader may have buffered data beyond metadata
	remainingBuf := make([]byte, bufReader.Buffered())
	_, _ = bufReader.Read(remainingBuf)
	dataReader := io.MultiReader(bytes.NewReader(remainingBuf), stream)

	// Bidirectional relay: stream <-> subprocess
	errChan := make(chan error, 2)

	// Stream -> Subprocess stdin
	go func() {
		_, err := io.Copy(stdinPipe, dataReader)
		stdinPipe.Close()
		errChan <- err
	}()

	// Subprocess stdout -> Stream
	go func() {
		_, err := tunnel.CopyBuffered(stream, stdoutPipe)
		errChan <- err
	}()

	// Wait for one direction to complete
	<-errChan
	log.Debug().Msgf("Tunnel stream closed for port %s.", targetPort)
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
		tc.session = nil
	}
	if tc.wsConn != nil {
		_ = tc.wsConn.WriteControl(
			websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""),
			time.Now().Add(5*time.Second),
		)
		_ = tc.wsConn.Close()
		tc.wsConn = nil
	}
}

// CloseTunnel closes an active tunnel by session ID.
func CloseTunnel(sessionID string) error {
	activeTunnelsMu.RLock()
	tc, exists := activeTunnels[sessionID]
	activeTunnelsMu.RUnlock()

	if !exists {
		return fmt.Errorf("tunnel session %s not found", sessionID)
	}

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
