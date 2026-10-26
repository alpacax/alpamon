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
	"net"
	"net/http"
	"os/exec"
	"regexp"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/alpacax/alpamon/v2/pkg/config"
	"github.com/alpacax/alpamon/v2/pkg/tunnel"
	"github.com/alpacax/alpamon/v2/pkg/utils"
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

var (
	errTunnelClosedWhileOpening = errors.New("tunnel session closed while opening")

	// validSessionID restricts session IDs to safe characters.
	validSessionID = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

	// activeTunnels tracks all active tunnel connections by session ID.
	activeTunnels   = make(map[string]*TunnelClient)
	activeTunnelsMu sync.RWMutex

	// globalStreamSem limits the total number of concurrent streams across all tunnel sessions.
	globalStreamSem = make(chan struct{}, maxGlobalStreams)
)

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
	clientType    string       // cli, web, editor
	targetPort    atomic.Int32 // for cli/web type
	username      string       // for editor type
	groupname     string       // for editor type
	serverURL     string
	requestHeader http.Header
	wsConn        *websocket.Conn
	session       *smux.Session
	ctx           context.Context
	cancel        context.CancelFunc
	codeServerMgr *CodeServerManager // for editor type
	connMu        sync.Mutex         // guards closed and the hand-off of wsConn, session and codeServerMgr from Open to Close
	closed        bool               // set by Close; Open installs nothing after it
	startRelay    func() error       // startTunnelRelay; replaced in tests
	daemonMu      sync.Mutex         // serializes daemon start against stop
	daemonCmd     *exec.Cmd
	daemonSocket  string        // UDS path, written before any stream reads it
	streamSem     chan struct{} // per-session stream concurrency limiter
	closeOnce     sync.Once     // ensures Close is executed only once
}

// IsValidSessionID reports whether sessionID is safe to use in paths and map keys.
func IsValidSessionID(sessionID string) bool {
	return validSessionID.MatchString(sessionID)
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
func NewTunnelClient(sessionID, clientType string, targetPort int, username, groupname, serverURL string) *TunnelClient {
	headers := http.Header{
		"Authorization": {fmt.Sprintf(`id="%s", key="%s"`, config.GlobalSettings.ID, config.GlobalSettings.Key)},
		"Origin":        {config.GlobalSettings.ServerURL},
	}

	ctx, cancel := context.WithCancel(context.Background())

	tc := &TunnelClient{
		sessionID:     sessionID,
		clientType:    clientType,
		username:      username,
		groupname:     groupname,
		serverURL:     serverURL,
		requestHeader: headers,
		ctx:           ctx,
		cancel:        cancel,
		streamSem:     make(chan struct{}, maxStreamsPerSession),
	}
	tc.targetPort.Store(int32(targetPort))
	tc.startRelay = tc.startTunnelRelay
	return tc
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

// Open connects a registered tunnel and starts its relay, failing when ctx ends or
// the tunnel closes before it finishes. On failure the tunnel is unregistered and closed.
func (tc *TunnelClient) Open(ctx context.Context) error {
	if err := tc.open(ctx); err != nil {
		tc.unregisterAndClose()
		return err
	}
	return nil
}

func (tc *TunnelClient) open(ctx context.Context) error {
	// For editor type, initialize code-server manager (startup triggered by health_check)
	if tc.clientType == ClientTypeEditor {
		if err := tc.initCodeServerManager(); err != nil {
			return err
		}
	}

	if err := tc.connect(ctx); err != nil {
		return err
	}

	log.Info().Msgf("Tunnel connection established for session %s, target port %d.", tc.sessionID, tc.targetPort.Load())

	if err := tc.startRelay(); err != nil {
		return fmt.Errorf("failed to start tunnel relay: %w", err)
	}

	tc.connMu.Lock()
	defer tc.connMu.Unlock()
	if tc.closed || !tc.isRegistered() { // CloseTunnel unregisters before Close sets closed
		return errTunnelClosedWhileOpening
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("tunnel open stopped: %w", err)
	}
	return nil
}

// Serve relays streams until the session ends, then unregisters and closes
// the tunnel. Call it only after Open succeeds.
func (tc *TunnelClient) Serve() {
	defer tc.unregisterAndClose()
	tc.handleStreams()
	log.Info().Msgf("Tunnel session %s ended.", tc.sessionID)
}

func (tc *TunnelClient) isRegistered() bool {
	activeTunnelsMu.RLock()
	defer activeTunnelsMu.RUnlock()
	return activeTunnels[tc.sessionID] == tc
}

// unregisterAndClose closes the tunnel and unregisters it only while it is the
// registered entry, so a newer tunnel under the same ID stays.
func (tc *TunnelClient) unregisterAndClose() {
	activeTunnelsMu.Lock()
	if activeTunnels[tc.sessionID] == tc {
		delete(activeTunnels, tc.sessionID)
	}
	activeTunnelsMu.Unlock()
	tc.Close()
}

// initCodeServerManager creates the code-server manager without starting it.
// The actual startup is triggered by health_check requests.
func (tc *TunnelClient) initCodeServerManager() error {
	mgr, err := NewCodeServerManager(tc.ctx, tc.username, tc.groupname)
	if err != nil {
		return fmt.Errorf("failed to create code-server manager: %w", err)
	}
	tc.connMu.Lock()
	defer tc.connMu.Unlock()
	if tc.closed {
		mgr.cancel()
		return errTunnelClosedWhileOpening
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
		tc.targetPort.Store(int32(tc.codeServerMgr.Port()))
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

const (
	smuxHeaderSize     = 8
	tunnelWSBufferSize = config.SmuxMaxFrameSize + smuxHeaderSize // gorilla adds its frame header on top
)

func newTunnelDialer() websocket.Dialer {
	return websocket.Dialer{
		Proxy:           utils.WebsocketProxy,
		ReadBufferSize:  tunnelWSBufferSize,
		WriteBufferSize: tunnelWSBufferSize,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: !config.GlobalSettings.SSLVerify,
		},
		HandshakeTimeout: 30 * time.Second,
	}
}

// connect establishes WebSocket connection and creates smux session.
func (tc *TunnelClient) connect(ctx context.Context) error {
	target, err := validateWebSocketURL(tc.serverURL)
	if err != nil {
		return fmt.Errorf("refused tunnel server URL: %w", err)
	}
	log.Info().Msgf("Connecting to tunnel server at %s...", ServerHostFromURL(target))

	dialCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(tc.ctx, cancel)
	defer stop()

	dialer := newTunnelDialer()
	// gorilla reads the handshake response without watching ctx, so a
	// canceled dial would otherwise wait out HandshakeTimeout.
	unwatch := func() bool { return true }
	dialer.NetDialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		c, err := (&net.Dialer{}).DialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		unwatch = context.AfterFunc(dialCtx, func() { _ = c.Close() })
		return c, nil
	}

	conn, resp, err := dialer.DialContext(dialCtx, target, tc.requestHeader)
	if !unwatch() || dialCtx.Err() != nil {
		if conn != nil {
			_ = conn.Close()
		}
		if tc.ctx.Err() != nil {
			return errTunnelClosedWhileOpening
		}
		return fmt.Errorf("tunnel dial stopped: %w", ctx.Err())
	}
	if err != nil {
		err = sanitizeURLError(err)
		if resp != nil {
			err = &handshakeError{StatusCode: resp.StatusCode, Err: err}
		}
		return fmt.Errorf("failed to connect to tunnel server: %w", err)
	}

	// Create smux client session over WebSocket
	wsNetConn := tunnel.NewWebSocketConn(conn)
	session, err := smux.Client(wsNetConn, config.GetSmuxConfig())
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("failed to create smux session: %w", err)
	}

	tc.connMu.Lock()
	defer tc.connMu.Unlock()
	if tc.closed {
		_ = session.Close()
		_ = conn.Close()
		return errTunnelClosedWhileOpening
	}
	tc.wsConn = conn
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
			_ = stream.Close()
			return
		}

		// Acquire global-level semaphore (block until slot available or context cancelled).
		select {
		case globalStreamSem <- struct{}{}:
		case <-tc.ctx.Done():
			<-tc.streamSem
			_ = stream.Close()
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

	targetAddr := net.JoinHostPort(loopbackHost, strconv.Itoa(targetPort))

	targetConn, err := tc.dialTunnelTarget(targetAddr)
	if err != nil {
		log.Debug().Err(err).Msgf("Failed to dial relay target %s.", targetAddr)
		return
	}
	defer func() { _ = targetConn.Close() }()

	log.Debug().Msgf("Relay target dialed for %s.", targetAddr)

	dataReader := tc.buildDataReader(bufReader, stream)
	tc.relayBidirectional(stream, targetConn, dataReader)

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
		return int(tc.targetPort.Load()), nil
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

func (tc *TunnelClient) relayBidirectional(stream *smux.Stream, targetConn net.Conn, dataReader io.Reader) {
	errChan := make(chan error, 2)

	// stream -> target
	go func() {
		_, err := tunnel.CopyBuffered(targetConn, dataReader)
		closeWriteSide(targetConn)
		errChan <- err
	}()

	// target -> stream
	go func() {
		_, err := tunnel.CopyBuffered(stream, targetConn)
		errChan <- err
	}()

	// Closing both ends unblocks the goroutine still copying.
	<-errChan
	_ = stream.Close()
	_ = targetConn.Close()
	<-errChan
}

// closeWriteSide signals EOF to the peer. The assertion covers *net.UnixConn
// (Unix daemon path) and *net.TCPConn (Windows direct path); anything else is
// left alone.
func closeWriteSide(conn net.Conn) {
	if cw, ok := conn.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	}
}

// Close cleanly shuts down the tunnel connection.
// Safe to call multiple times; only the first call performs cleanup.
func (tc *TunnelClient) Close() {
	tc.closeOnce.Do(func() {
		tc.connMu.Lock()
		tc.closed = true
		codeServerMgr, session, wsConn := tc.codeServerMgr, tc.session, tc.wsConn
		tc.connMu.Unlock()

		// Stop code-server first (for editor type)
		if codeServerMgr != nil {
			if err := codeServerMgr.Stop(); err != nil {
				log.Debug().Err(err).Msg("Failed to stop code-server.")
			}
		}

		// Cancel before stopping the relay so a not-yet-started
		// startTunnelRelay observes the closed context and never spawns.
		if tc.cancel != nil {
			tc.cancel()
		}

		// Unconditional: a no-op when no daemon is running.
		tc.stopTunnelRelay()
		if session != nil {
			_ = session.Close()
		}
		if wsConn != nil {
			_ = wsConn.WriteControl(
				websocket.CloseMessage,
				websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""),
				time.Now().Add(5*time.Second),
			)
			_ = wsConn.Close()
		}
	})
}

// CloseTunnel closes an active tunnel by session ID.
func CloseTunnel(sessionID string) error {
	activeTunnelsMu.Lock()
	tc, exists := activeTunnels[sessionID]
	if !exists {
		activeTunnelsMu.Unlock()
		return fmt.Errorf("tunnel session %s not found", sessionID)
	}
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

// CloseAllActiveTunnels closes all active tunnel connections.
// Called during graceful shutdown to ensure code-server and daemon processes are cleaned up.
func CloseAllActiveTunnels() {
	activeTunnelsMu.Lock()
	tunnels := make([]*TunnelClient, 0, len(activeTunnels))
	for _, tc := range activeTunnels {
		tunnels = append(tunnels, tc)
	}
	activeTunnels = make(map[string]*TunnelClient)
	activeTunnelsMu.Unlock()

	for _, tc := range tunnels {
		log.Info().Str("sessionID", tc.sessionID).Msg("Closing tunnel during shutdown.")
		tc.Close()
	}
}
