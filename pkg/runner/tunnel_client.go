package runner

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/alpacax/alpamon/pkg/config"
	"github.com/alpacax/alpamon/pkg/tunnel"
	"github.com/gorilla/websocket"
	"github.com/rs/zerolog/log"
	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/mem"
	"github.com/xtaci/smux"
)

const (
	// Stream metadata limit.
	maxMetadataSize = 1024

	// Stream concurrency limits.
	maxStreamsPerSession = 64
	maxGlobalStreams     = 256

	// System resource limits for tunnel session creation.
	maxCPUUsageForNewSession    = 90.0
	maxMemoryUsageForNewSession = 90.0

	// Client type constants for tunnel connections.
	ClientTypeCLI    = "cli"
	ClientTypeWeb    = "web"
	ClientTypeEditor = "editor"
)

// activeTunnels tracks all active tunnel connections by session ID.
var (
	activeTunnels   = make(map[string]*TunnelClient)
	activeTunnelsMu sync.RWMutex
)

// globalStreamSem limits the total number of concurrent streams across all tunnel sessions.
var globalStreamSem = make(chan struct{}, maxGlobalStreams)

// streamMetadata contains the target port information sent by the server.
type streamMetadata struct {
	RemotePort  string `json:"remote_port"`
	HealthCheck bool   `json:"health_check,omitempty"`
}

// healthResponse is the JSON body for health check responses.
type healthResponse struct {
	Status string `json:"status"`
	Error  string `json:"error,omitempty"`
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
	daemonCmd     *exec.Cmd          // tunnel daemon subprocess
	daemonSocket  string             // UDS path for daemon communication
	streamSem     chan struct{}      // per-session stream concurrency limiter
}

// CheckSystemResources verifies that system resources are within acceptable limits
// for creating a new tunnel session. Returns an error if CPU or memory usage exceeds thresholds.
// Uses fail-open policy: if resource metrics cannot be retrieved, the session is allowed.
func CheckSystemResources() error {
	cpuUsage, err := cpu.Percent(0, false)
	if err == nil && len(cpuUsage) > 0 && cpuUsage[0] > maxCPUUsageForNewSession {
		return fmt.Errorf("CPU usage %.1f%% exceeds limit %.0f%%", cpuUsage[0], maxCPUUsageForNewSession)
	}

	memInfo, err := mem.VirtualMemory()
	if err == nil && memInfo.UsedPercent > maxMemoryUsageForNewSession {
		return fmt.Errorf("memory usage %.1f%% exceeds limit %.0f%%", memInfo.UsedPercent, maxMemoryUsageForNewSession)
	}

	return nil
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
		streamSem:     make(chan struct{}, maxStreamsPerSession),
	}
}

// RegisterTunnel atomically checks for an existing tunnel and registers a new one.
// Returns false if a tunnel with the same session ID already exists.
func RegisterTunnel(sessionID string, tc *TunnelClient) bool {
	activeTunnelsMu.Lock()
	defer activeTunnelsMu.Unlock()
	if _, exists := activeTunnels[sessionID]; exists {
		return false
	}
	activeTunnels[sessionID] = tc
	return true
}

// RunTunnelBackground starts the tunnel connection in a goroutine.
// The caller must register the tunnel via RegisterTunnel before calling this method.
func (tc *TunnelClient) RunTunnelBackground() {
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

	// Start tunnel daemon (single subprocess for all streams)
	if err := tc.startTunnelDaemon(); err != nil {
		log.Error().Err(err).Msgf("Failed to start tunnel daemon for session %s.", tc.sessionID)
		return
	}

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
	data, err := json.Marshal(healthResponse{Status: status, Error: errMsg})
	if err != nil {
		return `{"status":"error"}`
	}
	return string(data)
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

		tc.logStreamPressure()

		// Acquire session-level semaphore (block until slot available or context cancelled).
		select {
		case tc.streamSem <- struct{}{}:
		case <-tc.ctx.Done():
			stream.Close()
			return
		}

		// Acquire global-level semaphore (block until slot available or context cancelled).
		select {
		case globalStreamSem <- struct{}{}:
		case <-tc.ctx.Done():
			<-tc.streamSem
			stream.Close()
			return
		}

		go func() {
			defer func() {
				<-globalStreamSem
				<-tc.streamSem
			}()
			tc.handleStream(stream)
		}()
	}
}

// logStreamPressure logs a warning when stream concurrency approaches limits.
func (tc *TunnelClient) logStreamPressure() {
	sessionCount := len(tc.streamSem)
	globalCount := len(globalStreamSem)

	if sessionCount >= maxStreamsPerSession*3/4 {
		log.Warn().
			Int("session_streams", sessionCount).
			Int("max_session_streams", maxStreamsPerSession).
			Str("session_id", tc.sessionID).
			Msg("Session stream count approaching limit.")
	}

	if globalCount >= maxGlobalStreams*3/4 {
		log.Warn().
			Int("global_streams", globalCount).
			Int("max_global_streams", maxGlobalStreams).
			Msg("Global stream count approaching limit.")
	}
}

// handleStream processes a single smux stream by connecting to the tunnel daemon
// via Unix domain socket and relaying data to the local service.
func (tc *TunnelClient) handleStream(stream *smux.Stream) {
	defer stream.Close()

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

	// Connect to tunnel daemon via UDS (daemon runs as nobody user for security)
	daemonConn, err := tc.connectToDaemon(targetAddr)
	if err != nil {
		log.Debug().Err(err).Msgf("Failed to connect to tunnel daemon for %s.", targetAddr)
		return
	}
	defer daemonConn.Close()

	log.Debug().Msgf("Connected to tunnel daemon for %s.", targetAddr)

	dataReader := tc.buildDataReader(bufReader, stream)
	tc.relayBidirectional(stream, daemonConn, dataReader)

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

func (tc *TunnelClient) relayBidirectional(stream *smux.Stream, daemonConn net.Conn, dataReader io.Reader) {
	errChan := make(chan error, 2)

	// stream -> daemon (via UDS)
	go func() {
		_, err := tunnel.CopyBuffered(daemonConn, dataReader)
		// Half-close the write side to signal EOF to daemon
		if uc, ok := daemonConn.(*net.UnixConn); ok {
			_ = uc.CloseWrite()
		}
		errChan <- err
	}()

	// daemon -> stream (via UDS)
	go func() {
		_, err := tunnel.CopyBuffered(stream, daemonConn)
		errChan <- err
	}()

	<-errChan
}

// startTunnelDaemon starts a tunnel daemon subprocess for this session.
// The daemon runs with demoted credentials and handles all stream relay via UDS.
func (tc *TunnelClient) startTunnelDaemon() error {
	tc.daemonSocket = fmt.Sprintf("/tmp/alpamon-tunnel-%s.sock", tc.sessionID)

	cmd, err := spawnTunnelDaemon(tc.daemonSocket)
	if err != nil {
		return fmt.Errorf("failed to spawn tunnel daemon: %w", err)
	}
	tc.daemonCmd = cmd

	if err := tc.waitForDaemonReady(); err != nil {
		// Daemon failed to start, clean up
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		os.Remove(tc.daemonSocket)
		return fmt.Errorf("tunnel daemon not ready: %w", err)
	}

	log.Info().Msgf("Tunnel daemon ready for session %s, socket: %s.", tc.sessionID, tc.daemonSocket)
	return nil
}

// waitForDaemonReady polls the UDS socket until the daemon is accepting connections.
func (tc *TunnelClient) waitForDaemonReady() error {
	deadline := time.Now().Add(5 * time.Second)

	for time.Now().Before(deadline) {
		conn, err := net.Dial("unix", tc.daemonSocket)
		if err == nil {
			conn.Close()
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}

	return fmt.Errorf("timeout waiting for daemon socket %s", tc.daemonSocket)
}

// connectToDaemon connects to the tunnel daemon via UDS and sends the target address.
func (tc *TunnelClient) connectToDaemon(targetAddr string) (net.Conn, error) {
	conn, err := net.Dial("unix", tc.daemonSocket)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to daemon socket: %w", err)
	}

	if _, err := fmt.Fprintf(conn, "%s\n", targetAddr); err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to send target address to daemon: %w", err)
	}

	return conn, nil
}

// stopTunnelDaemon gracefully stops the tunnel daemon subprocess.
func (tc *TunnelClient) stopTunnelDaemon() {
	if tc.daemonCmd == nil || tc.daemonCmd.Process == nil {
		return
	}

	log.Info().Msgf("Stopping tunnel daemon for session %s...", tc.sessionID)

	if err := tc.daemonCmd.Process.Signal(syscall.SIGTERM); err != nil {
		log.Debug().Err(err).Msg("SIGTERM failed for tunnel daemon, trying SIGKILL.")
		_ = tc.daemonCmd.Process.Kill()
	}

	done := make(chan error, 1)
	go func() {
		done <- tc.daemonCmd.Wait()
	}()

	select {
	case <-done:
		log.Info().Msg("Tunnel daemon stopped.")
	case <-time.After(10 * time.Second):
		_ = tc.daemonCmd.Process.Kill()
		log.Warn().Msg("Tunnel daemon killed after timeout.")
	}

	os.Remove(tc.daemonSocket)
	tc.daemonCmd = nil
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

	// Stop tunnel daemon
	if tc.daemonCmd != nil {
		tc.stopTunnelDaemon()
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
