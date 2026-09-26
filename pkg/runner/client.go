package runner

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/alpacax/alpamon/v2/internal/pool"
	"github.com/alpacax/alpamon/v2/internal/protocol"
	"github.com/alpacax/alpamon/v2/pkg/agent"
	"github.com/alpacax/alpamon/v2/pkg/config"
	"github.com/alpacax/alpamon/v2/pkg/executor/handlers/common"
	"github.com/alpacax/alpamon/v2/pkg/scheduler"
	"github.com/alpacax/alpamon/v2/pkg/signing"
	"github.com/alpacax/alpamon/v2/pkg/utils"
	"github.com/gorilla/websocket"
	"github.com/rs/zerolog/log"
)

// handlerOutcome carries what a message handler wants done with the connection.
// Only the read loop acts on it; the handler never closes or replaces the connection.
type handlerOutcome int

const (
	outcomeContinue handlerOutcome = iota
	outcomeReconnect
)

type WebsocketClient struct {
	// mu guards Conn and keepalive: Connect writes them from the read loop; Close reads Conn on shutdown.
	mu sync.Mutex
	// Conn stays exported for outside readers; inside this package use the accessors.
	//
	// Deprecated: use SetReadDeadline, ReadMessage and WriteJSON.
	Conn *websocket.Conn
	// keepalive belongs to Conn and is replaced with it. Nil for a Conn that Connect did not install.
	keepalive *connKeepalive

	// dial opens a connection; nil means dialWebsocket. Tests swap in a dialer that wraps the socket.
	dial func(ctx context.Context, url string, header http.Header) (*websocket.Conn, error)

	// lastPeerReconnect is owned by the read loop goroutine alone: one read
	// loop per client, so it needs no lock.
	lastPeerReconnect time.Time

	requestHeader        http.Header
	apiSession           *scheduler.Session
	RestartChan          chan struct{}
	ShutDownChan         chan struct{}
	CollectorRestartChan chan struct{}
	pool                 *pool.Pool
	ctxManager           *agent.ContextManager
	dispatcher           CommandDispatcher
	keyManager           *signing.KeyManager
	signingMode          string
	serverID             string

	// connectBackoff outlives a single Connect call: the escalation after
	// repeated rejections is only visible across reconnects.
	connectBackoff *authBackoff

	// onAuthenticated holds a callback invoked from RunForever after the
	// first successful ReadMessage on each new connection. Used by the
	// workspace-migration watchdog to detect that the new workspace's
	// WebSocket is not merely dial-able but actually streaming traffic
	// (i.e. auth and any in-front-of proxies accepted the agent). The
	// hook must be idempotent because it fires on every reconnect.
	//
	// Stored as an atomic.Pointer so concurrent SetOnAuthenticated calls
	// from outside the RunForever goroutine race-safely with Connect.
	onAuthenticated atomic.Pointer[func()]

	// terminalOnce lets only the first of ShutDown and Restart through: root.go
	// waits on both channels in one select, so closing both picks at random.
	terminalOnce sync.Once
}

const (
	minConnectInterval    = 5 * time.Second
	maxConnectInterval    = 60 * time.Second
	ConnectionReadTimeout = 35 * time.Minute

	eventCommandAckURL    = "/api/events/commands/%s/ack/"
	eventCommandFinURL    = "/api/events/commands/%s/fin/"
	eventCommandRejectURL = "/api/events/commands/%s/reject/"
	eventCommandChunkURL  = "/api/events/commands/%s/chunk/"
)

// Keepalive timings. keepaliveInterval is how often the agent pings the
// current connection; keepaliveTimeout is how long it waits for any frame,
// pongs included, once the peer has answered a ping. Vars, not consts, so
// tests can shrink them instead of waiting out real minutes.
var (
	keepaliveInterval = 30 * time.Second
	keepaliveTimeout  = 120 * time.Second
)

// keepaliveWriteWait bounds one ping write, including the wait for a
// WriteJSON that holds the writer.
const keepaliveWriteWait = 10 * time.Second

// connKeepalive is the keepalive state of one connection. Each connection
// gets its own, so a pong on a replaced connection can never shorten the
// deadline of the one that replaced it.
type connKeepalive struct {
	// pongSeen flips once the peer answers a ping. Until then the read loop
	// keeps ConnectionReadTimeout, so a peer that never answers pings is
	// treated exactly as before keepalive existed.
	pongSeen atomic.Bool
}

// readTimeout is the deadline the read loop arms before each read.
func (k *connKeepalive) readTimeout() time.Duration {
	if k != nil && k.pongSeen.Load() {
		return keepaliveTimeout
	}
	return ConnectionReadTimeout
}

// expired reports whether a read failed because a peer that has answered
// pings went quiet for keepaliveTimeout. Once a pong has arrived the pong
// handler keeps the deadline at keepaliveTimeout, so any read timeout from
// then on is this one.
func (k *connKeepalive) expired(err error) bool {
	if k == nil || !k.pongSeen.Load() {
		return false
	}
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

// peerReconnectMinInterval paces peer-requested reconnects: the console can
// ask for one in a loop, and connectForever only paces failed dials. A var,
// not a const, so tests can shrink it instead of running at real pacing.
var peerReconnectMinInterval = 5 * time.Second

func NewWebsocketClient(session *scheduler.Session, ctxManager *agent.ContextManager, workerPool *pool.Pool) *WebsocketClient {
	headers := http.Header{
		"Authorization": {fmt.Sprintf(`id="%s", key="%s"`, config.GlobalSettings.ID, config.GlobalSettings.Key)},
		"Origin":        {config.GlobalSettings.ServerURL},
		"User-Agent":    {utils.GetUserAgent("alpamon")},
	}

	wc := &WebsocketClient{
		requestHeader:        headers,
		apiSession:           session,
		RestartChan:          make(chan struct{}),
		ShutDownChan:         make(chan struct{}),
		CollectorRestartChan: make(chan struct{}, 1),
		pool:                 workerPool,
		ctxManager:           ctxManager,
		signingMode:          config.GlobalSettings.SigningMode,
		serverID:             config.GlobalSettings.ID,
		connectBackoff:       newAuthBackoff(minConnectInterval, maxConnectInterval),
	}

	// Local environments (localhost) have no AI signing server, so enforce
	// mode would reject all commands. Auto-downgrade to monitor mode.
	if signing.IsLocalEnv(config.GlobalSettings.ServerURL) && wc.signingMode == "enforce" {
		wc.signingMode = "monitor"
		log.Warn().Msg("Local environment detected, downgrading signing mode to monitor.")
	}

	wc.keyManager = signing.NewKeyManager(
		config.GlobalSettings.AIServerURL,
		config.GlobalSettings.KeyRefreshSecs,
		signing.ResolveAuthEnv(config.GlobalSettings.ServerURL),
		utils.NewHTTPClient(),
	)
	log.Info().Str("mode", wc.signingMode).Msg("Command signature verification enabled.")

	return wc
}

// SetDispatcher sets the dispatcher for handling commands with dispatcher
func (wc *WebsocketClient) SetDispatcher(dispatcher CommandDispatcher) {
	wc.dispatcher = dispatcher
}

// SetOnAuthenticated registers a callback invoked from RunForever after
// the first successful ReadMessage of each connection. Firing here rather
// than at dial-time gives the migration watchdog a strong "the new
// workspace really did accept us" signal: an upgrade-then-immediate-close
// scenario (auth rejected by a downstream proxy, rate-limit, etc.) never
// produces a ReadMessage and so never confirms.
//
// The callback must be idempotent — it fires on every reconnect, not only
// the first one. Passing nil clears it. Safe to call from any goroutine.
func (wc *WebsocketClient) SetOnAuthenticated(fn func()) {
	if fn == nil {
		wc.onAuthenticated.Store(nil)
		return
	}
	wc.onAuthenticated.Store(&fn)
}

func (wc *WebsocketClient) conn() *websocket.Conn {
	wc.mu.Lock()
	defer wc.mu.Unlock()
	return wc.Conn
}

// connState returns the current connection with its keepalive state.
func (wc *WebsocketClient) connState() (*websocket.Conn, *connKeepalive) {
	wc.mu.Lock()
	defer wc.mu.Unlock()
	return wc.Conn, wc.keepalive
}

// swapConn returns the replaced conn; the caller must close it.
func (wc *WebsocketClient) swapConn(conn *websocket.Conn) *websocket.Conn {
	return wc.installConn(conn, nil)
}

// installConn makes conn current together with its keepalive state and
// returns the replaced conn; the caller must close it.
func (wc *WebsocketClient) installConn(conn *websocket.Conn, ka *connKeepalive) *websocket.Conn {
	wc.mu.Lock()
	defer wc.mu.Unlock()
	old := wc.Conn
	wc.Conn = conn
	wc.keepalive = ka
	return old
}

// SetReadLimit caps one inbound frame. A new connection starts uncapped, so
// callers reapply it after every reconnect.
func (wc *WebsocketClient) SetReadLimit(limit int64) {
	conn := wc.conn()
	if conn == nil {
		return
	}
	conn.SetReadLimit(limit)
}

// SetReadDeadline arms the read timeout for the current connection. It reports
// net.ErrClosed when there is no connection to arm.
func (wc *WebsocketClient) SetReadDeadline(t time.Time) error {
	conn := wc.conn()
	if conn == nil {
		return net.ErrClosed
	}
	return conn.SetReadDeadline(t)
}

func (wc *WebsocketClient) RunForever(ctx context.Context) {
	if err := wc.Connect(ctx); err != nil {
		return
	}
	// authenticatedThisConn flips true after the first successful read on
	// the current connection. Cleared by CloseAndReconnect so the next
	// connection has to re-prove itself before onAuthenticated fires.
	authenticatedThisConn := false

	for {
		select {
		case <-ctx.Done():
			return
		default:
			conn, ka := wc.connState()
			if err := conn.SetReadDeadline(time.Now().Add(ka.readTimeout())); err != nil {
				if err = wc.CloseAndReconnect(ctx); err != nil {
					return
				}
				authenticatedThisConn = false
				continue
			}
			_, message, err := conn.ReadMessage()
			if err != nil {
				if ka.expired(err) {
					err = wc.reconnectAfterSilence(ctx, conn)
				} else {
					err = wc.CloseAndReconnect(ctx)
				}
				if err != nil {
					return
				}
				authenticatedThisConn = false
				continue
			}
			if !authenticatedThisConn {
				authenticatedThisConn = true
				if cb := wc.onAuthenticated.Load(); cb != nil {
					(*cb)()
				}
			}
			if wc.commandRequestHandler(message) == outcomeReconnect {
				if err := wc.CloseAndReconnectOnRequest(ctx); err != nil {
					return
				}
				authenticatedThisConn = false
			}
		}
	}
}

func (wc *WebsocketClient) SendPingQuery() error {
	pingQuery := map[string]string{"query": "ping"}
	err := wc.WriteJSON(pingQuery)
	if err != nil {
		return err
	}

	return nil
}

func (wc *WebsocketClient) SendPongResponse() error {
	pongResponse := map[string]string{
		"query":     "pong",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	}
	return wc.WriteJSON(pongResponse)
}

// ReadMessage reads the next frame on the current connection. It reports
// net.ErrClosed when there is no connection to read.
func (wc *WebsocketClient) ReadMessage() (messageType int, message []byte, err error) {
	conn := wc.conn()
	if conn == nil {
		return 0, nil, net.ErrClosed
	}
	return conn.ReadMessage()
}

// Connect dials until the connection is established, and returns an error
// only when ctx ends first. Repeated rejections slow it down rather than
// stop it; see connectForever.
func (wc *WebsocketClient) Connect(ctx context.Context) error {
	log.Info().Msgf("Connecting to websocket at %s...", config.GlobalSettings.WSPath)

	dial := wc.dial
	if dial == nil {
		dial = dialWebsocket
	}

	return connectForever(ctx, wc.connectBackoff, config.GlobalSettings.WSPath, func() error {
		conn, err := dial(ctx, config.GlobalSettings.WSPath, wc.requestHeader)
		if err != nil {
			return err
		}

		ka := &connKeepalive{}
		// The pong handler runs inside ReadMessage, on the read loop, so it may arm the read deadline.
		conn.SetPongHandler(func(string) error {
			ka.pongSeen.Store(true)
			return conn.SetReadDeadline(time.Now().Add(keepaliveTimeout))
		})

		if old := wc.installConn(conn, ka); old != nil {
			// Already closed on the reconnect path; net.ErrClosed is the expected answer there.
			if err := old.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
				log.Debug().Err(err).Msg("Failed to close the connection Connect replaced.")
			}
		}
		go wc.sendPings(ctx, conn, keepaliveInterval)
		log.Debug().Msg("Backhaul connection established.")
		return nil
	})
}

// sendPings pings conn every interval until conn stops being the current
// connection or ctx ends. A failed ping, such as a write that timed out
// behind a long WriteJSON, needs no handling here: the pong it did not earn
// lets the read deadline expire, and the read loop owns reconnecting.
// WriteControl is safe to call alongside WriteJSON.
func (wc *WebsocketClient) sendPings(ctx context.Context, conn *websocket.Conn, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}

		if wc.conn() != conn {
			return
		}
		_ = conn.WriteControl(websocket.PingMessage, nil, time.Now().Add(keepaliveWriteWait))
	}
}

// reconnectAfterSilence drops a connection whose peer stopped answering and
// dials a new one. It sends no close frame: on a link that fails in one
// direction only, the frame could still reach Alpacon and read as the agent
// closing on purpose. Call it only from the read loop.
func (wc *WebsocketClient) reconnectAfterSilence(ctx context.Context, conn *websocket.Conn) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	log.Warn().Msg("No response from Alpacon for 2 minutes; reconnecting.")

	if err := conn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		log.Debug().Err(err).Msg("Failed to close the unresponsive websocket connection.")
	}

	if err := wc.connectBackoff.waitBeforeRedial(ctx); err != nil {
		return err
	}
	return wc.Connect(ctx)
}

// CloseAndReconnect drains the peer's close reply, so it reads the socket:
// call it only from the goroutine that owns the reads.
func (wc *WebsocketClient) CloseAndReconnect(ctx context.Context) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	wc.closeAndDrain()
	return wc.Connect(ctx)
}

// CloseAndReconnectOnRequest paces a peer-requested reconnect, so a console
// repeating the reconnect query cannot drive an unbounded dial loop.
// Call it only from the read loop: it calls CloseAndReconnect, which owns the reads.
func (wc *WebsocketClient) CloseAndReconnectOnRequest(ctx context.Context) error {
	// A zero lastPeerReconnect makes wait negative, so the first request never pauses.
	if wait := peerReconnectMinInterval - time.Since(wc.lastPeerReconnect); wait > 0 {
		timer := time.NewTimer(wait)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
		}
	}

	wc.lastPeerReconnect = time.Now()
	return wc.CloseAndReconnect(ctx)
}

// Close sends a close frame and closes the connection. It does not drain the
// peer's reply: only the read loop may read, and Close runs outside it.
func (wc *WebsocketClient) Close() {
	wc.closeConn(false)
}

// closeAndDrain also waits for the peer's close reply, so it reads the socket:
// call it only from the goroutine that owns the reads.
func (wc *WebsocketClient) closeAndDrain() {
	wc.closeConn(true)
}

func (wc *WebsocketClient) closeConn(drain bool) {
	conn := wc.conn()
	if conn == nil {
		return
	}

	err := conn.WriteControl(
		websocket.CloseMessage,
		websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""),
		time.Now().Add(5*time.Second),
	)
	if err != nil {
		log.Debug().Err(err).Msg("Failed to write close message to websocket.")
	} else if drain {
		drainCloseReply(conn)
	}

	// Close unconditionally so a broken connection cannot leak its fd; net.ErrClosed only means the reconnect path already closed it.
	if err = conn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		log.Debug().Err(err).Msg("Failed to close websocket connection.")
	}
}

func drainCloseReply(conn *websocket.Conn) {
	// A pong arriving now must not stretch the drain to keepaliveTimeout.
	conn.SetPongHandler(nil)
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second)) // the peer only answers a close frame that actually went out
	for {
		if _, _, err := conn.NextReader(); err != nil {
			break
		}
	}
}

func (wc *WebsocketClient) ShutDown() {
	wc.terminalOnce.Do(func() { close(wc.ShutDownChan) })
}

func (wc *WebsocketClient) Restart() {
	wc.terminalOnce.Do(func() { close(wc.RestartChan) })
}

func (wc *WebsocketClient) RestartCollector() {
	select {
	case wc.CollectorRestartChan <- struct{}{}:
	default:
		log.Info().Msg("Collector restart already requested, skipping duplicate signal.")
	}
}

func (wc *WebsocketClient) commandRequestHandler(message []byte) handlerOutcome {
	if len(message) == 0 {
		return outcomeContinue
	}

	msg, err := protocol.ParseMessage(message)
	if err != nil {
		log.Warn().Err(err).Msgf("Inappropriate message: %s.", string(message))
		return outcomeContinue
	}

	switch msg.Query {
	case protocol.MessageTypePing:
		// Respond to ping with pong
		if err := wc.SendPongResponse(); err != nil {
			log.Debug().Err(err).Msg("Failed to send pong response.")
		}
	case protocol.MessageTypeCommand:
		if msg.Command == nil {
			log.Warn().Msg("Command message without command data")
			return outcomeContinue
		}

		// Verify signature before ACK
		if err := wc.verifyCommandSignature(msg.Command); err != nil {
			// Log the full error chain locally; err.Error() returns only
			// the fixed rejection reason, Unwrap() has the detailed cause.
			var rejection *rejectionError
			if errors.As(err, &rejection) {
				log.Error().Err(rejection.Unwrap()).
					Str("command_id", msg.Command.ID).
					Str("reason", rejection.reason).
					Msg("Command signature verification failed.")
			} else {
				log.Error().Err(err).Str("command_id", msg.Command.ID).
					Msg("Command signature verification failed.")
			}
			wc.rejectCommand(msg.Command.ID, err.Error())
			return outcomeContinue
		}

		scheduler.Rqueue.Post(fmt.Sprintf(eventCommandAckURL, msg.Command.ID),
			nil,
			10,
			time.Time{},
		)

		data, err := msg.Command.ParseCommandData()
		if err != nil {
			log.Warn().Err(err).Msgf("Failed to parse command data: %s.", string(message))
			return outcomeContinue
		}

		// Use modular handler system
		if wc.dispatcher != nil {
			wc.handleCommand(*msg.Command, *data)
		} else {
			log.Error().Msg("Dispatcher not initialized")
			// Send failure notification
			payload := protocol.NewCommandResponse(false, "Internal error: dispatcher not initialized", 0, 1)
			scheduler.Rqueue.Post(fmt.Sprintf(eventCommandFinURL, msg.Command.ID),
				payload,
				10,
				time.Time{},
			)
		}
	case protocol.MessageTypeQuit:
		log.Debug().Msgf("Quit requested for reason: %s.", msg.Reason)
		wc.ShutDown()
	case protocol.MessageTypeReconnect:
		log.Debug().Msgf("Reconnect requested for reason: %s.", msg.Reason)
		return outcomeReconnect
	default:
		log.Warn().Msgf("Not implemented query: %s.", msg.Query)
	}

	return outcomeContinue
}

// WriteJSON writes data as a JSON frame on the current connection. It reports
// net.ErrClosed when there is no connection to write.
func (wc *WebsocketClient) WriteJSON(data any) error {
	conn := wc.conn()
	if conn == nil {
		return net.ErrClosed
	}
	if err := conn.WriteJSON(data); err != nil {
		log.Debug().Err(err).Msgf("Failed to write json data to websocket.")
		return err
	}
	return nil
}

func (wc *WebsocketClient) handleCommand(command protocol.Command, data protocol.CommandData) {
	// Create CommandRunner with dispatcher for direct execution
	commandRunner := NewCommandRunner(wc, wc.apiSession, command, data, wc.dispatcher)

	// Each handler manages its own timeout; safety net prevents leaked goroutines.
	// When PoolDefaultTimeout > 0, ensure it always exceeds the longest handler
	// timeout (ShellTimeout) so handler-level timeouts fire before the safety net.
	// When PoolDefaultTimeout == 0, the safety net is explicitly disabled by config.
	safetyTimeout := time.Duration(config.GlobalSettings.PoolDefaultTimeout) * time.Second
	if safetyTimeout > 0 {
		minSafetyTimeout := common.ShellTimeout + 5*time.Minute
		if safetyTimeout < minSafetyTimeout {
			safetyTimeout = minSafetyTimeout
		}
	}
	ctx, cancel := wc.ctxManager.NewContext(safetyTimeout)

	err := wc.pool.Submit(ctx, func() error {
		defer cancel()
		// Run the command - it handles result notification internally via defer
		return commandRunner.Run(ctx)
	})

	if err != nil {
		cancel()
		log.Error().Err(err).Msgf("Failed to submit command %s to pool", command.ID)
		// Send failure notification
		start := time.Now()
		payload := protocol.NewCommandResponse(false, fmt.Sprintf("Failed to submit command: %v", err), time.Since(start).Seconds(), 1)
		scheduler.Rqueue.Post(fmt.Sprintf(eventCommandFinURL, command.ID),
			payload,
			10,
			time.Time{},
		)
	}
}
