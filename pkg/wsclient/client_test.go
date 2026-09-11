package wsclient

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alpacax/alpamon/v2/pkg/version"
	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// These tests talk to a real httptest server, so they run on the real clock:
// a synctest bubble does not count a socket wait as blocked. The backoff
// schedule itself is timed under a fake clock in reconnect_test.go.

const waitFor = 5 * time.Second

// backhaulServer is a websocket test double for the Alpacon backhaul. Every
// connection it accepts is handed to the test over accepted.
type backhaulServer struct {
	url            string
	accepted       chan *serverConn
	upgrades       atomic.Int32
	reject         atomic.Int32 // answer this many upgrades with 503 first
	closeOnAccept  atomic.Bool  // accept the upgrade, then close straight away
	frameThenClose atomic.Bool  // send one data frame, then close
	stallNext      atomic.Bool  // never read the next connection, so the client's writes back up
	done           chan struct{}
}

// serverConn is the server's end of one accepted connection. The test may
// write to conn from one goroutine; the server's own goroutine does the reading.
type serverConn struct {
	conn      *websocket.Conn
	header    http.Header
	frames    atomic.Int64 // every frame read, including any received had no room for
	received  chan []byte  // the first frames read; never blocks the server's reads
	closeCode chan int
}

func newBackhaulServer(t *testing.T) *backhaulServer {
	t.Helper()
	s := &backhaulServer{accepted: make(chan *serverConn, 1024), done: make(chan struct{})}
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.reject.Load() > 0 {
			s.reject.Add(-1)
			http.Error(w, "backhaul restarting", http.StatusServiceUnavailable)
			return
		}
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		s.upgrades.Add(1)

		sc := &serverConn{
			conn:      conn,
			header:    r.Header.Clone(),
			received:  make(chan []byte, 1024),
			closeCode: make(chan int, 1),
		}
		conn.SetCloseHandler(func(code int, _ string) error {
			sc.closeCode <- code
			// SetCloseHandler replaces gorilla's default reply; answer so the client's drain ends at once.
			_ = conn.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(code, ""), time.Now().Add(time.Second))
			return nil
		})
		s.accepted <- sc
		if s.frameThenClose.Load() {
			_ = conn.WriteMessage(websocket.TextMessage, []byte("hi"))
			_ = conn.WriteControl(websocket.CloseMessage,
				websocket.FormatCloseMessage(websocket.CloseGoingAway, "bye"),
				time.Now().Add(time.Second))
			return
		}
		if s.closeOnAccept.Load() {
			_ = conn.WriteControl(websocket.CloseMessage,
				websocket.FormatCloseMessage(websocket.CloseTryAgainLater, "at capacity"),
				time.Now().Add(time.Second))
			return
		}
		if s.stallNext.CompareAndSwap(true, false) {
			<-s.done
			return
		}

		for {
			_, msg, err := conn.ReadMessage()
			if err != nil {
				return
			}
			sc.frames.Add(1)
			select {
			case sc.received <- msg:
			default: // a flooding test only samples; stalling here would stall the client's writes
			}
		}
	}))
	t.Cleanup(ts.Close)
	t.Cleanup(func() { close(s.done) }) // runs before ts.Close, releasing stalled handlers

	s.url = strings.Replace(ts.URL, "http", "ws", 1)
	return s
}

func (sc *serverConn) push(t *testing.T, messageType int, payload string) {
	t.Helper()
	require.NoError(t, sc.conn.WriteMessage(messageType, []byte(payload)))
}

// hooks records what a client reports through its Config hooks.
type hooks struct {
	connects    chan struct{}
	disconnects chan error
	retries     chan retryEvent
}

type retryEvent struct {
	attempt int
	delay   time.Duration
	err     error
}

func newHooks() *hooks {
	return &hooks{
		connects:    make(chan struct{}, 1024),
		disconnects: make(chan error, 1024),
		retries:     make(chan retryEvent, 1024),
	}
}

func (h *hooks) install(cfg *Config) {
	cfg.OnConnect = func() { h.connects <- struct{}{} }
	cfg.OnDisconnect = func(err error) { h.disconnects <- err }
	cfg.OnRetry = func(attempt int, delay time.Duration, err error) {
		h.retries <- retryEvent{attempt: attempt, delay: delay, err: err}
	}
}

// recv waits for one value from ch, failing the test if none arrives.
func recv[T any](t *testing.T, ch <-chan T, what string) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(waitFor):
		t.Fatal("timed out waiting for " + what)
		var zero T
		return zero
	}
}

func testConfig(url string) Config {
	return Config{
		URL:        url,
		ID:         "srv-1",
		Key:        "secret",
		Origin:     "https://alpacon.example.com",
		MinBackoff: 10 * time.Millisecond,
		MaxBackoff: 50 * time.Millisecond,
	}
}

func discard(context.Context, int, []byte) error { return nil }

// startClient builds a client from cfg and runs it with h, returning the
// channel Run's result arrives on. Cleanup shuts the client down and waits.
func startClient(t *testing.T, ctx context.Context, cfg Config, h Handler) (*Client, <-chan error) {
	t.Helper()
	c, err := New(cfg)
	require.NoError(t, err)

	result := make(chan error, 1)
	go func() { result <- c.Run(ctx, h) }()
	t.Cleanup(func() {
		c.Shutdown()
		select {
		case <-c.Done():
		case <-time.After(waitFor):
			t.Fatal("Run did not return after Shutdown")
		}
	})
	return c, result
}

// closeTrackingDialer records whether the socket under each connection it
// opens was closed, which is how a leaked fd shows up in a test.
type closeTrackingDialer struct {
	mu     sync.Mutex
	closed []*atomic.Bool
}

func (d *closeTrackingDialer) dialer() *websocket.Dialer {
	ws := DefaultDialer()
	var nd net.Dialer
	ws.NetDialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		conn, err := nd.DialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		flag := &atomic.Bool{}
		d.mu.Lock()
		d.closed = append(d.closed, flag)
		d.mu.Unlock()
		return closeTrackingConn{Conn: conn, closed: flag}, nil
	}
	return ws
}

func (d *closeTrackingDialer) allClosed() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, flag := range d.closed {
		if !flag.Load() {
			return false
		}
	}
	return len(d.closed) > 0
}

type closeTrackingConn struct {
	net.Conn
	closed *atomic.Bool
}

func (c closeTrackingConn) Close() error {
	c.closed.Store(true)
	return c.Conn.Close()
}

// readDeadlineProofConn ignores read deadlines, so a test can keep a read
// parked through the interrupt a pending request would otherwise use to free
// it, and decide for itself what the read returns.
type readDeadlineProofConn struct{ net.Conn }

func (readDeadlineProofConn) SetReadDeadline(time.Time) error { return nil }

// Only the first connection is made deadline-proof: a later one has to stay
// interruptible, or Shutdown could never free the read loop parked on it.
func readDeadlineProofDialer() *websocket.Dialer {
	d := DefaultDialer()
	var nd net.Dialer
	var used atomic.Bool
	d.NetDialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		conn, err := nd.DialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		if used.CompareAndSwap(false, true) {
			return readDeadlineProofConn{conn}, nil
		}
		return conn, nil
	}
	return d
}

// deadlineRefusingConn accepts a fixed number of read deadlines and then
// refuses every one, the way a caller-supplied net.Conn that does not
// implement deadlines behaves.
type deadlineRefusingConn struct {
	net.Conn
	allow *atomic.Int32
}

func (c deadlineRefusingConn) SetReadDeadline(t time.Time) error {
	if c.allow.Add(-1) >= 0 {
		return c.Conn.SetReadDeadline(t)
	}
	return errors.New("this conn does not do deadlines")
}

func deadlineRefusingDialer(allow *atomic.Int32) *websocket.Dialer {
	d := DefaultDialer()
	var nd net.Dialer
	d.NetDialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		conn, err := nd.DialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		return deadlineRefusingConn{Conn: conn, allow: allow}, nil
	}
	return d
}

// undeadlinedConn ignores deadlines, so a test can hold a handshake open
// past the point where the client would otherwise abort it.
type undeadlinedConn struct{ net.Conn }

func (undeadlinedConn) SetDeadline(time.Time) error { return nil }

// countingConn counts Read calls on the client's socket, so a test can tell
// when the read loop has actually entered a read.
type countingConn struct {
	net.Conn
	reads *atomic.Int64
}

func (c countingConn) Read(p []byte) (int, error) {
	c.reads.Add(1)
	return c.Conn.Read(p)
}

func countingDialer(reads *atomic.Int64) *websocket.Dialer {
	d := DefaultDialer()
	var nd net.Dialer
	d.NetDialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		conn, err := nd.DialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		return countingConn{Conn: conn, reads: reads}, nil
	}
	return d
}

// parkedClient starts a client and returns once Run is inside a read on its
// first connection, with the default 35-minute read deadline armed. Anything
// that ends Run from there has to free that read.
func parkedClient(t *testing.T, ctx context.Context, srv *backhaulServer, h *hooks) (*Client, <-chan error, *serverConn) {
	t.Helper()
	var reads, readsAtConnect atomic.Int64
	cfg := testConfig(srv.url)
	h.install(&cfg)
	cfg.Dialer = countingDialer(&reads)
	onConnect := cfg.OnConnect
	cfg.OnConnect = func() {
		// OnConnect runs on the Run goroutine after the handshake's last read
		// and before the first ReadMessage, so this is the handshake's count.
		readsAtConnect.Store(reads.Load())
		onConnect()
	}

	c, result := startClient(t, ctx, cfg, discard)
	recv(t, h.connects, "the first connect")
	sc := recv(t, srv.accepted, "the first connection")
	require.Eventually(t, func() bool { return reads.Load() > readsAtConnect.Load() },
		waitFor, time.Millisecond, "Run never entered its read")
	return c, result, sc
}

func TestClient_SendsTheHandshakeHeaders(t *testing.T) {
	srv := newBackhaulServer(t)
	startClient(t, t.Context(), testConfig(srv.url), discard)

	sc := recv(t, srv.accepted, "a connection")
	assert.Equal(t, `id="srv-1", key="secret"`, sc.header.Get("Authorization"))
	assert.Equal(t, "https://alpacon.example.com", sc.header.Get("Origin"))
	assert.Equal(t, "alpamon/"+version.Version, sc.header.Get("User-Agent"))
}

func TestClient_DeliversFramesInOrder(t *testing.T) {
	type frame struct {
		messageType int
		payload     string
	}
	srv := newBackhaulServer(t)
	got := make(chan frame, 8)
	startClient(t, t.Context(), testConfig(srv.url), func(_ context.Context, mt int, p []byte) error {
		got <- frame{mt, string(p)}
		return nil
	})

	sc := recv(t, srv.accepted, "a connection")
	sc.push(t, websocket.TextMessage, "one")
	sc.push(t, websocket.TextMessage, "two")
	sc.push(t, websocket.BinaryMessage, "three")

	assert.Equal(t, frame{websocket.TextMessage, "one"}, recv(t, got, "the first frame"))
	assert.Equal(t, frame{websocket.TextMessage, "two"}, recv(t, got, "the second frame"))
	assert.Equal(t, frame{websocket.BinaryMessage, "three"}, recv(t, got, "the third frame"))
}

func TestClient_WriteJSONReachesTheServer(t *testing.T) {
	srv := newBackhaulServer(t)
	h := newHooks()
	cfg := testConfig(srv.url)
	h.install(&cfg)
	c, _ := startClient(t, t.Context(), cfg, discard)

	recv(t, h.connects, "the connect")
	sc := recv(t, srv.accepted, "a connection")
	require.NoError(t, c.WriteJSON(map[string]string{"query": "ping"}))
	assert.JSONEq(t, `{"query":"ping"}`, string(recv(t, sc.received, "the frame")))
}

func TestClient_WriteWithoutAConnection(t *testing.T) {
	c, err := New(validConfig())
	require.NoError(t, err)

	assert.ErrorIs(t, c.WriteMessage(websocket.TextMessage, []byte("x")), ErrNotConnected)
	assert.ErrorIs(t, c.WriteJSON(map[string]string{"query": "ping"}), ErrNotConnected)
	assert.False(t, c.Connected())
}

func TestClient_WriteJSONReportsAnEncodingError(t *testing.T) {
	c, err := New(validConfig())
	require.NoError(t, err)

	var unsupported *json.UnsupportedTypeError
	assert.ErrorAs(t, c.WriteJSON(make(chan int)), &unsupported, "an encoding error must come back before any frame is attempted")
}

// TestClient_WriteMessageRejectsControlFrames keeps the lifecycle with the
// Client: gorilla/websocket would send a close frame handed to WriteMessage,
// and every later write would fail while the read loop still counted the
// connection as live.
func TestClient_WriteMessageRejectsControlFrames(t *testing.T) {
	srv := newBackhaulServer(t)
	h := newHooks()
	cfg := testConfig(srv.url)
	h.install(&cfg)
	c, _ := startClient(t, t.Context(), cfg, discard)
	recv(t, h.connects, "the connect")
	sc := recv(t, srv.accepted, "the connection")

	for _, mt := range []int{websocket.CloseMessage, websocket.PingMessage, websocket.PongMessage, 99} {
		assert.ErrorContains(t, c.WriteMessage(mt, nil), "data frames only", "message type %d", mt)
	}

	require.NoError(t, c.WriteJSON(map[string]string{"query": "ping"}), "the connection must be untouched")
	assert.JSONEq(t, `{"query":"ping"}`, string(recv(t, sc.received, "the frame")))
	select {
	case code := <-sc.closeCode:
		assert.Fail(t, "a rejected control frame reached the server", "close code %d", code)
	default:
	}
}

// TestClient_FailedWriteReplacesTheConnection covers a peer that stops
// reading. The write must give up at WriteTimeout instead of holding the
// write lock forever, and because a failed write leaves the connection unable
// to send, Run must replace it straight away, not 35 minutes later when the
// read side times out.
func TestClient_FailedWriteReplacesTheConnection(t *testing.T) {
	srv := newBackhaulServer(t)
	srv.stallNext.Store(true)
	h := newHooks()
	var tracker closeTrackingDialer
	cfg := testConfig(srv.url)
	cfg.WriteTimeout = 200 * time.Millisecond
	cfg.Dialer = tracker.dialer()
	h.install(&cfg)
	c, _ := startClient(t, t.Context(), cfg, discard)
	recv(t, h.connects, "the first connect")
	recv(t, srv.accepted, "the stalled connection")

	// Far more than the loopback socket buffers hold, so the write has to block.
	err := c.WriteMessage(websocket.BinaryMessage, make([]byte, 64<<20))

	var netErr net.Error
	require.ErrorAs(t, err, &netErr, "a write to a peer that stopped reading must time out, not hang")
	assert.True(t, netErr.Timeout())
	assert.ErrorIs(t, recv(t, h.disconnects, "the disconnect"), err, "the failed write is what ended the connection")
	recv(t, h.connects, "the replacement connect")
	sc := recv(t, srv.accepted, "the replacement connection")
	require.NoError(t, c.WriteJSON(map[string]string{"query": "ping"}))
	assert.JSONEq(t, `{"query":"ping"}`, string(recv(t, sc.received, "a frame on the replacement")))

	// The abandoned connection could not send its close frame, since its
	// write side was already dead. Its socket must be closed all the same,
	// or every failed write leaks an fd.
	c.Shutdown()
	recv(t, c.Done(), "Run to return")
	assert.True(t, tracker.allClosed(), "every socket the client opened must be closed")
}

// TestClient_ShutdownFreesAParkedRead is the regression for issue #452's
// first two items. pkg/runner's client closes the connection from whatever
// goroutine calls Close, racing the read loop for the conn field and for the
// socket itself. Here Shutdown comes from the test goroutine while Run sits in
// a read with 35 minutes left on its deadline, and it must end Run at once and
// cleanly.
func TestClient_ShutdownFreesAParkedRead(t *testing.T) {
	srv := newBackhaulServer(t)
	h := newHooks()
	c, result, sc := parkedClient(t, t.Context(), srv, h)
	require.True(t, c.Connected())

	c.Shutdown()

	require.NoError(t, recv(t, result, "Run to return"), "Run returns nil after Shutdown")
	assert.NoError(t, recv(t, h.disconnects, "the disconnect"), "a requested close reports no error")
	assert.Equal(t, websocket.CloseNormalClosure, recv(t, sc.closeCode, "the close frame"))
	assert.False(t, c.Connected())
	select {
	case <-c.Done():
	default:
		assert.Fail(t, "Done must be closed once Run has returned")
	}
}

func TestClient_ContextCancelFreesAParkedRead(t *testing.T) {
	srv := newBackhaulServer(t)
	h := newHooks()
	ctx, cancel := context.WithCancel(t.Context())
	_, result, sc := parkedClient(t, ctx, srv, h)

	cancel()

	require.ErrorIs(t, recv(t, result, "Run to return"), context.Canceled)
	assert.NoError(t, recv(t, h.disconnects, "the disconnect"), "a requested close reports no error")
	assert.Equal(t, websocket.CloseNormalClosure, recv(t, sc.closeCode, "the close frame"))
}

// TestClient_ShutdownAbortsAStalledHandshake covers a peer that completes the
// TCP connect and then never answers the upgrade. gorilla/websocket stops
// watching the context at that point, so only HandshakeTimeout would end the
// wait, and this dialer has none: without an abort of its own the client
// would hang here forever, and a pod would be killed mid-shutdown.
func TestClient_ShutdownAbortsAStalledHandshake(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })
	accepted := make(chan net.Conn, 8)
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			accepted <- conn // never answer the upgrade
		}
	}()

	cfg := testConfig("ws://" + listener.Addr().String() + "/ws/")
	cfg.Dialer = &websocket.Dialer{} // no HandshakeTimeout, so nothing else can end the wait
	c, result := startClient(t, t.Context(), cfg, discard)
	stalled := recv(t, accepted, "the connection the client opened")
	t.Cleanup(func() { _ = stalled.Close() })

	c.Shutdown()

	require.NoError(t, recv(t, result, "Run to return"))
}

// TestClient_AbortSurvivesTheHandshakeDeadline covers the window the plain
// abort misses. When the dialer has a handshake timeout, gorilla sets its own
// deadline on the socket after the dial hook returns, outside this package's
// wrapper: an abort that landed in between would be silently overwritten and
// the dial would run to that timeout instead of ending at once.
func TestClient_AbortSurvivesTheHandshakeDeadline(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })
	accepted := make(chan net.Conn, 8)
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			accepted <- conn // never answer the upgrade
		}
	}()

	const handshakeTimeout = 2 * time.Second
	var c *Client
	ready := make(chan struct{})
	cfg := testConfig("ws://" + listener.Addr().String() + "/ws/")
	cfg.Dialer = &websocket.Dialer{HandshakeTimeout: handshakeTimeout}
	cfg.Dialer.NetDialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		<-ready
		var nd net.Dialer
		conn, err := nd.DialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		// Abort while the socket is already open but before it is handed
		// back, which is exactly the window gorilla's own deadline lands in.
		c.Shutdown()
		<-ctx.Done()
		time.Sleep(50 * time.Millisecond) // let the abort reach the socket
		return conn, nil
	}
	c, err = New(cfg)
	require.NoError(t, err)
	result := make(chan error, 1)
	go func() { result <- c.Run(t.Context(), discard) }()
	close(ready)

	start := time.Now()
	require.NoError(t, recv(t, result, "Run to return"))
	assert.Less(t, time.Since(start), handshakeTimeout,
		"the abort must hold, not be overwritten by the handshake deadline")
}

// TestClient_GivesUpAConnectionWhoseDeadlineWontArm covers a
// caller-supplied conn that refuses a read deadline. Reading anyway would
// park with no timeout, and every way of freeing a parked read sets that
// same deadline, so Run and Done would block for good.
func TestClient_GivesUpAConnectionWhoseDeadlineWontArm(t *testing.T) {
	srv := newBackhaulServer(t)
	h := newHooks()
	var allow atomic.Int32 // refuse from the very first arm
	cfg := testConfig(srv.url)
	cfg.Dialer = deadlineRefusingDialer(&allow)
	h.install(&cfg)
	startClient(t, t.Context(), cfg, discard)

	recv(t, h.connects, "the connect")
	recv(t, srv.accepted, "the connection")
	assert.ErrorContains(t, recv(t, h.disconnects, "the disconnect"), "arming the read deadline")
	recv(t, srv.accepted, "the redial, rather than a read that could never end")
}

// TestClient_ShutdownClosesAConnThatWontTakeADeadline covers the same
// refusal arriving later: the read is already parked on a deadline that was
// accepted once, and the interrupt that should free it is refused. Closing
// the socket is the only thing left that ends the read.
func TestClient_ShutdownClosesAConnThatWontTakeADeadline(t *testing.T) {
	srv := newBackhaulServer(t)
	h := newHooks()
	var allow atomic.Int32
	allow.Store(1) // the first arm succeeds, every interrupt after it fails
	cfg := testConfig(srv.url)
	cfg.ReadTimeout = 30 * time.Second // far past the test's patience
	cfg.Dialer = deadlineRefusingDialer(&allow)
	h.install(&cfg)
	c, result := startClient(t, t.Context(), cfg, discard)
	recv(t, h.connects, "the connect")
	recv(t, srv.accepted, "the connection")
	time.Sleep(50 * time.Millisecond) // let the read park

	c.Shutdown()

	require.NoError(t, recv(t, result, "Run to return"))
}

// TestClient_ShutdownIsIdempotent is the regression for issue #452's third
// item: pkg/runner's ShutDown closes a channel and panics the second time.
func TestClient_ShutdownIsIdempotent(t *testing.T) {
	srv := newBackhaulServer(t)
	h := newHooks()
	c, result, _ := parkedClient(t, t.Context(), srv, h)

	var wg sync.WaitGroup
	for range 8 {
		wg.Go(c.Shutdown)
	}
	wg.Wait()

	require.NoError(t, recv(t, result, "Run to return"))
	assert.NotPanics(t, c.Shutdown, "Shutdown after Run returned")
}

func TestClient_ShutdownBeforeRunNeverDials(t *testing.T) {
	srv := newBackhaulServer(t)
	var dials atomic.Int32
	cfg := testConfig(srv.url)
	cfg.Dialer = DefaultDialer()
	cfg.Dialer.NetDialContext = func(context.Context, string, string) (net.Conn, error) {
		dials.Add(1)
		return nil, errors.New("dialed after Shutdown")
	}
	c, err := New(cfg)
	require.NoError(t, err)

	c.Shutdown()
	require.NoError(t, c.Run(t.Context(), discard))

	assert.Zero(t, dials.Load(), "a client shut down before Run must not dial")
}

// TestClient_ShutdownDuringADialNeverConnects holds a dial open across
// Shutdown and then lets it succeed. The connection it produces must be
// closed unannounced: an OnConnect after Shutdown would flip a caller's
// connected gauge back to 1 for a connection that is already going away.
func TestClient_ShutdownDuringADialNeverConnects(t *testing.T) {
	srv := newBackhaulServer(t)
	dialing := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	var connects, disconnects atomic.Int32
	cfg := testConfig(srv.url)
	cfg.OnConnect = func() { connects.Add(1) }
	cfg.OnDisconnect = func(error) { disconnects.Add(1) }
	cfg.Dialer = DefaultDialer()
	cfg.Dialer.NetDialContext = func(_ context.Context, network, addr string) (net.Conn, error) {
		once.Do(func() { close(dialing) })
		<-release
		// Ignore the cancelled dial context, and refuse the deadline the
		// abort would force, so the handshake always completes: this is the
		// case where the connection is already established when Shutdown
		// lands, which is the one install has to refuse.
		var nd net.Dialer
		conn, err := nd.DialContext(context.Background(), network, addr)
		if err != nil {
			return nil, err
		}
		return undeadlinedConn{conn}, nil
	}
	c, err := New(cfg)
	require.NoError(t, err)
	result := make(chan error, 1)
	go func() { result <- c.Run(t.Context(), discard) }()

	recv(t, dialing, "the dial to start")
	c.Shutdown()
	close(release)

	require.NoError(t, recv(t, result, "Run to return"))
	assert.Zero(t, connects.Load(), "a connection that completes after Shutdown must not be announced")
	assert.Zero(t, disconnects.Load(), "and it must not be mourned either: OnDisconnect belongs to an announced connection")
	assert.False(t, c.Connected())
	sc := recv(t, srv.accepted, "the connection the held dial produced")
	assert.Equal(t, websocket.CloseNormalClosure, recv(t, sc.closeCode, "its close frame"), "it must still be closed cleanly")
}

func TestClient_RunIsSingleUse(t *testing.T) {
	c, err := New(validConfig())
	require.NoError(t, err)
	c.Shutdown()

	require.NoError(t, c.Run(t.Context(), discard))
	assert.ErrorIs(t, c.Run(t.Context(), discard), ErrAlreadyRunning)
}

func TestClient_RunRejectsANilHandler(t *testing.T) {
	c, err := New(validConfig())
	require.NoError(t, err)

	assert.ErrorContains(t, c.Run(t.Context(), nil), "non-nil Handler")
	select {
	case <-c.Done():
	default:
		assert.Fail(t, "Done must close even when Run refuses to start")
	}
}

func TestClient_HandlerErrorStopsRun(t *testing.T) {
	srv := newBackhaulServer(t)
	h := newHooks()
	cfg := testConfig(srv.url)
	h.install(&cfg)
	errStop := errors.New("unparseable command")
	_, result := startClient(t, t.Context(), cfg, func(context.Context, int, []byte) error { return errStop })

	sc := recv(t, srv.accepted, "a connection")
	sc.push(t, websocket.TextMessage, "garbage")

	require.ErrorIs(t, recv(t, result, "Run to return"), errStop)
	assert.ErrorIs(t, recv(t, h.disconnects, "the disconnect"), errStop, "OnDisconnect names what ended the connection")
	assert.Equal(t, websocket.CloseNormalClosure, recv(t, sc.closeCode, "the close frame"))
}

func TestClient_ReconnectDialsAFreshConnection(t *testing.T) {
	srv := newBackhaulServer(t)
	h := newHooks()
	got := make(chan string, 8)
	cfg := testConfig(srv.url)
	h.install(&cfg)
	c, _ := startClient(t, t.Context(), cfg, func(_ context.Context, _ int, p []byte) error {
		got <- string(p)
		return nil
	})
	recv(t, h.connects, "the first connect")
	first := recv(t, srv.accepted, "the first connection")

	c.Reconnect()

	assert.Equal(t, websocket.CloseNormalClosure, recv(t, first.closeCode, "the close frame on the old connection"))
	assert.NoError(t, recv(t, h.disconnects, "the disconnect"), "a requested reconnect reports no error")
	recv(t, h.connects, "the second connect")
	second := recv(t, srv.accepted, "the second connection")
	second.push(t, websocket.TextMessage, "after reconnect")
	assert.Equal(t, "after reconnect", recv(t, got, "a frame on the new connection"))
}

// TestClient_ShutdownCancelsTheHandlerContext covers the handler contract in
// both directions: Shutdown has to release a handler blocked on its context,
// and a handler that reports that cancellation is not failing. Run must still
// return nil, and the disconnect is a requested one, not an error.
func TestClient_ShutdownCancelsTheHandlerContext(t *testing.T) {
	srv := newBackhaulServer(t)
	h := newHooks()
	cfg := testConfig(srv.url)
	h.install(&cfg)
	started := make(chan struct{}, 1)
	c, result := startClient(t, t.Context(), cfg, func(ctx context.Context, _ int, _ []byte) error {
		started <- struct{}{}
		<-ctx.Done()
		return ctx.Err()
	})
	recv(t, h.connects, "the connect")
	recv(t, srv.accepted, "the connection").push(t, websocket.TextMessage, "work")
	recv(t, started, "the handler to block on its context")

	c.Shutdown()

	require.NoError(t, recv(t, result, "Run to return"),
		"a handler reporting the cancellation that is already stopping Run has not failed")
	assert.NoError(t, recv(t, h.disconnects, "the disconnect"))
}

func TestClient_ContextCancelReachesTheHandler(t *testing.T) {
	srv := newBackhaulServer(t)
	ctx, cancel := context.WithCancel(t.Context())
	started := make(chan struct{}, 1)
	_, result := startClient(t, ctx, testConfig(srv.url), func(ctx context.Context, _ int, _ []byte) error {
		started <- struct{}{}
		<-ctx.Done()
		return ctx.Err()
	})
	recv(t, srv.accepted, "the connection").push(t, websocket.TextMessage, "work")
	recv(t, started, "the handler to block on its context")

	cancel()

	assert.ErrorIs(t, recv(t, result, "Run to return"), context.Canceled)
}

// TestClient_ReportsThePeersCloseCode keeps the disconnect cause honest: a
// close code the server chose must reach OnDisconnect, not be flattened into
// the nil of a requested close.
func TestClient_ReportsThePeersCloseCode(t *testing.T) {
	srv := newBackhaulServer(t)
	h := newHooks()
	cfg := testConfig(srv.url)
	h.install(&cfg)
	startClient(t, t.Context(), cfg, discard)
	recv(t, h.connects, "the connect")
	sc := recv(t, srv.accepted, "the connection")

	require.NoError(t, sc.conn.WriteControl(websocket.CloseMessage,
		websocket.FormatCloseMessage(websocket.ClosePolicyViolation, "revoked"),
		time.Now().Add(time.Second)))

	err := recv(t, h.disconnects, "the disconnect")
	var closeErr *websocket.CloseError
	require.ErrorAs(t, err, &closeErr)
	assert.Equal(t, websocket.ClosePolicyViolation, closeErr.Code)
	assert.Equal(t, "revoked", closeErr.Text)
}

// TestClient_PrefersThePeersReasonOverAPendingRequest pins which of two
// simultaneous endings gets reported. A write fails, which marks the
// connection for replacement, and only then does the peer's close arrive.
// The close carries the reason an operator needs, so it must win: reporting
// the write error instead would hide "revoked" behind "i/o timeout".
func TestClient_PrefersThePeersReasonOverAPendingRequest(t *testing.T) {
	srv := newBackhaulServer(t)
	srv.stallNext.Store(true)
	h := newHooks()
	cfg := testConfig(srv.url)
	cfg.WriteTimeout = 200 * time.Millisecond
	cfg.Dialer = readDeadlineProofDialer()
	h.install(&cfg)
	c, _ := startClient(t, t.Context(), cfg, discard)
	recv(t, h.connects, "the connect")
	sc := recv(t, srv.accepted, "the stalled connection")

	// The peer has stopped reading, so this write times out and marks the
	// connection for replacement while the read stays parked.
	require.Error(t, c.WriteMessage(websocket.BinaryMessage, make([]byte, 64<<20)))
	require.NoError(t, sc.conn.WriteControl(websocket.CloseMessage,
		websocket.FormatCloseMessage(websocket.ClosePolicyViolation, "revoked"),
		time.Now().Add(time.Second)))

	err := recv(t, h.disconnects, "the disconnect")
	var closeErr *websocket.CloseError
	require.ErrorAs(t, err, &closeErr, "the peer's close must outrank the pending write failure")
	assert.Equal(t, "revoked", closeErr.Text)
}

// TestClient_ReconnectFromTheHandler is how a plugin answers the server's
// "reconnect" query: from inside the handler, between two reads. The request
// lands before the loop re-arms its read deadline, so it only takes effect if
// the loop checks for it before arming; otherwise the next read parks with a
// fresh 35 minutes and the reconnect never happens.
func TestClient_ReconnectFromTheHandler(t *testing.T) {
	srv := newBackhaulServer(t)
	h := newHooks()
	cfg := testConfig(srv.url)
	h.install(&cfg)
	var c *Client
	ready := make(chan struct{})
	c, _ = startClient(t, t.Context(), cfg, func(_ context.Context, _ int, p []byte) error {
		<-ready
		if string(p) == `{"query":"reconnect"}` {
			c.Reconnect()
		}
		return nil
	})
	close(ready)
	recv(t, h.connects, "the first connect")
	first := recv(t, srv.accepted, "the first connection")

	first.push(t, websocket.TextMessage, `{"query":"reconnect"}`)

	assert.Equal(t, websocket.CloseNormalClosure, recv(t, first.closeCode, "the close frame on the old connection"))
	assert.NoError(t, recv(t, h.disconnects, "the disconnect"))
	recv(t, srv.accepted, "the connection the handler asked for")
}

// TestClient_ShutdownFromTheHandler is the "quit" query: Shutdown from inside
// the handler, before the loop's next read.
func TestClient_ShutdownFromTheHandler(t *testing.T) {
	srv := newBackhaulServer(t)
	var c *Client
	ready := make(chan struct{})
	c, result := startClient(t, t.Context(), testConfig(srv.url), func(context.Context, int, []byte) error {
		<-ready
		c.Shutdown()
		return nil
	})
	close(ready)
	sc := recv(t, srv.accepted, "the connection")

	sc.push(t, websocket.TextMessage, `{"query":"quit"}`)

	require.NoError(t, recv(t, result, "Run to return"))
	assert.Equal(t, websocket.CloseNormalClosure, recv(t, sc.closeCode, "the close frame"))
}

// TestClient_ReconnectIsNotHeldUpByASilentPeer bounds the close handshake.
// When the close is noticed between reads, the connection is still healthy,
// so the drain really does wait on the peer, and the peer least likely to
// answer is the draining backhaul that asked for the reconnect. Waiting the
// full close timeout there would black out every agent in the fleet for it.
func TestClient_ReconnectIsNotHeldUpByASilentPeer(t *testing.T) {
	srv := newBackhaulServer(t)
	srv.stallNext.Store(true) // accepts, then neither reads nor answers the close
	h := newHooks()
	cfg := testConfig(srv.url)
	h.install(&cfg)
	var c *Client
	ready := make(chan struct{})
	c, _ = startClient(t, t.Context(), cfg, func(context.Context, int, []byte) error {
		<-ready
		c.Reconnect()
		return nil
	})
	close(ready)
	recv(t, h.connects, "the first connect")
	first := recv(t, srv.accepted, "the stalled connection")
	first.push(t, websocket.TextMessage, `{"query":"reconnect"}`)

	start := time.Now()
	recv(t, h.connects, "the reconnect")
	assert.Less(t, time.Since(start), 3*time.Second,
		"the drain must give up on a peer that never answers the close frame")
}

func TestClient_ReconnectWithoutAConnectionDoesNothing(t *testing.T) {
	c, err := New(validConfig())
	require.NoError(t, err)

	c.Reconnect()

	c.mu.Lock()
	defer c.mu.Unlock()
	assert.False(t, c.reconnectPending, "a request with nothing to drop must not linger and cut the next connection short")
}

func TestClient_RedialsAfterTheServerDropsTheConnection(t *testing.T) {
	srv := newBackhaulServer(t)
	h := newHooks()
	got := make(chan string, 8)
	cfg := testConfig(srv.url)
	h.install(&cfg)
	startClient(t, t.Context(), cfg, func(_ context.Context, _ int, p []byte) error {
		got <- string(p)
		return nil
	})
	recv(t, h.connects, "the first connect")
	first := recv(t, srv.accepted, "the first connection")

	require.NoError(t, first.conn.UnderlyingConn().Close())

	assert.Error(t, recv(t, h.disconnects, "the disconnect"), "a dropped connection reports why")
	recv(t, h.connects, "the second connect")
	second := recv(t, srv.accepted, "the second connection")
	second.push(t, websocket.TextMessage, "after redial")
	assert.Equal(t, "after redial", recv(t, got, "a frame on the new connection"))
}

func TestClient_ReadTimeoutTriggersAReconnect(t *testing.T) {
	srv := newBackhaulServer(t)
	h := newHooks()
	cfg := testConfig(srv.url)
	cfg.ReadTimeout = 100 * time.Millisecond
	h.install(&cfg)
	startClient(t, t.Context(), cfg, discard)
	recv(t, srv.accepted, "the first connection")

	err := recv(t, h.disconnects, "the disconnect")
	var netErr net.Error
	require.ErrorAs(t, err, &netErr, "a silent peer must surface as a read failure, not a requested close")
	assert.True(t, netErr.Timeout())
	recv(t, srv.accepted, "the connection dialed after the timeout")
}

// TestClient_PingFramesKeepTheConnectionAlive covers a peer whose keepalive
// is an RFC 6455 ping rather than a data frame. gorilla answers pings inside
// ReadMessage without returning, so the read deadline is only re-armed once
// a read completes: without a ping handler of our own, a peer that pings
// steadily still gets dropped at ReadTimeout.
func TestClient_PingFramesKeepTheConnectionAlive(t *testing.T) {
	srv := newBackhaulServer(t)
	h := newHooks()
	cfg := testConfig(srv.url)
	cfg.ReadTimeout = 150 * time.Millisecond
	h.install(&cfg)
	c, _ := startClient(t, t.Context(), cfg, discard)
	recv(t, h.connects, "the connect")
	sc := recv(t, srv.accepted, "the connection")

	// Pings spanning well over two read timeouts, and no data frame at all.
	for deadline := time.Now().Add(400 * time.Millisecond); time.Now().Before(deadline); {
		require.NoError(t, sc.conn.WriteControl(websocket.PingMessage, nil, time.Now().Add(time.Second)))
		time.Sleep(50 * time.Millisecond)
	}

	select {
	case err := <-h.disconnects:
		assert.Fail(t, "a peer that keeps pinging must not hit the read timeout", "disconnected with %v", err)
	default:
	}
	assert.True(t, c.Connected())
}

func TestClient_ReadLimitDropsAnOversizedFrame(t *testing.T) {
	srv := newBackhaulServer(t)
	h := newHooks()
	cfg := testConfig(srv.url)
	cfg.ReadLimit = 16
	h.install(&cfg)
	startClient(t, t.Context(), cfg, discard)
	sc := recv(t, srv.accepted, "the first connection")

	sc.push(t, websocket.TextMessage, strings.Repeat("x", 64))

	assert.ErrorIs(t, recv(t, h.disconnects, "the disconnect"), websocket.ErrReadLimit)
	recv(t, srv.accepted, "the connection dialed after the drop")
}

func TestClient_RetriesARejectedHandshakeThenConnects(t *testing.T) {
	srv := newBackhaulServer(t)
	srv.reject.Store(2)
	h := newHooks()
	cfg := testConfig(srv.url)
	cfg.Rand = func() float64 { return 0 } // factor 0.5, so the first waits clamp to MinBackoff
	h.install(&cfg)
	delivered := make(chan struct{}, 1)
	startClient(t, t.Context(), cfg, func(context.Context, int, []byte) error {
		delivered <- struct{}{}
		return nil
	})

	first := recv(t, h.retries, "the first retry")
	second := recv(t, h.retries, "the second retry")
	assert.Equal(t, 1, first.attempt)
	assert.Equal(t, 2, second.attempt)
	require.ErrorIs(t, first.err, websocket.ErrBadHandshake)
	assert.ErrorContains(t, first.err, "HTTP 503", "the status is what tells an outage from a revoked key")
	recv(t, h.connects, "the connect after the rejections")
	sc := recv(t, srv.accepted, "the connection")

	// A connection that lasts at least MinBackoff has proved itself, which
	// resets the schedule: after the next drop, counting and waiting both
	// start over instead of continuing from where they stopped.
	sc.push(t, websocket.TextMessage, "traffic")
	recv(t, delivered, "the frame")
	time.Sleep(cfg.MinBackoff + 10*time.Millisecond) // age it past the proof window
	srv.reject.Store(1)
	require.NoError(t, sc.conn.UnderlyingConn().Close())
	require.Error(t, recv(t, h.disconnects, "the drop"))
	third := recv(t, h.retries, "the retry after the drop")
	assert.Equal(t, 1, third.attempt, "attempt counting restarts after a connection")
	assert.Equal(t, cfg.MinBackoff, third.delay, "the wait restarts at the floor after a connection")
	recv(t, h.connects, "the reconnect")
}

// TestClient_PacesRedialsAfterAnUnprovenConnection is the regression for a
// reconnect storm. A peer that accepts the handshake and closes at once used
// to be redialed with no wait at all, because the backoff only ever applied
// between failed dials: thousands of upgrades a second, per agent, and
// OnRetry silent throughout. A connection that ends before it proved itself
// must now be followed by the same backoff a failed dial gets.
func TestClient_PacesRedialsAfterAnUnprovenConnection(t *testing.T) {
	srv := newBackhaulServer(t)
	srv.closeOnAccept.Store(true)
	h := newHooks()
	cfg := testConfig(srv.url)
	cfg.MinBackoff = 200 * time.Millisecond
	cfg.MaxBackoff = time.Minute
	cfg.Rand = func() float64 { return 0 } // factor 1.0, so waits are the base
	h.install(&cfg)
	startClient(t, t.Context(), cfg, discard)

	// Two rounds of accept-then-close, each paced and reported.
	for _, want := range []time.Duration{200 * time.Millisecond, 400 * time.Millisecond} {
		recv(t, h.connects, "a connect")
		require.Error(t, recv(t, h.disconnects, "the close the server sent"))
		r := recv(t, h.retries, "the wait before the redial")
		assert.Equal(t, want, r.delay, "an unproven connection must back off, and keep doubling")
	}
	assert.Less(t, srv.upgrades.Load(), int32(10), "a paced loop cannot have run away")
}

// TestClient_RedialsAtOnceAfterAProvenConnection keeps the other half of the
// rule honest: pacing must not slow recovery for a connection that was
// working, which is every ordinary drop.
func TestClient_RedialsAtOnceAfterAProvenConnection(t *testing.T) {
	srv := newBackhaulServer(t)
	h := newHooks()
	cfg := testConfig(srv.url)
	cfg.MinBackoff = 50 * time.Millisecond
	cfg.MaxBackoff = 50 * time.Millisecond
	h.install(&cfg)
	startClient(t, t.Context(), cfg, discard)
	recv(t, h.connects, "the first connect")
	first := recv(t, srv.accepted, "the first connection")

	time.Sleep(cfg.MinBackoff + 20*time.Millisecond) // age it past the proof window
	require.NoError(t, first.conn.UnderlyingConn().Close())

	require.Error(t, recv(t, h.disconnects, "the drop"))
	recv(t, h.connects, "the immediate redial")
	select {
	case r := <-h.retries:
		assert.Fail(t, "a proven connection must be redialed without waiting", "waited %s", r.delay)
	default:
	}
}

// TestClient_PacesARedialAfterAFailedWrite is the regression for a write
// failure jumping the queue. A failed write asks for the connection to be
// replaced, the same as Reconnect does, but it is a failure: routing it
// through the caller-requested path reset the backoff and redialed with no
// wait at all, which is a storm against a backhaul whose write side is sick.
func TestClient_PacesARedialAfterAFailedWrite(t *testing.T) {
	srv := newBackhaulServer(t)
	srv.stallNext.Store(true)
	h := newHooks()
	cfg := testConfig(srv.url)
	cfg.WriteTimeout = 100 * time.Millisecond
	cfg.MinBackoff = 300 * time.Millisecond
	cfg.MaxBackoff = time.Minute
	cfg.Rand = func() float64 { return 0 } // factor 1.0, so the wait is the base
	h.install(&cfg)
	c, _ := startClient(t, t.Context(), cfg, discard)
	recv(t, h.connects, "the first connect")
	recv(t, srv.accepted, "the stalled connection")

	require.Error(t, c.WriteMessage(websocket.BinaryMessage, make([]byte, 64<<20)))

	require.Error(t, recv(t, h.disconnects, "the disconnect"))
	r := recv(t, h.retries, "the wait before the redial")
	assert.Equal(t, 1, r.attempt)
	assert.Equal(t, cfg.MinBackoff, r.delay, "a failed write must be paced like any other failure")
}

// TestClient_AFrameDoesNotProveAConnection is the regression for the rule
// that decides pacing. Counting frames as proof let a peer send one byte,
// hang up, and have the backoff reset every round: a redial loop bounded by
// nothing.
func TestClient_AFrameDoesNotProveAConnection(t *testing.T) {
	srv := newBackhaulServer(t)
	srv.frameThenClose.Store(true)
	h := newHooks()
	cfg := testConfig(srv.url)
	cfg.MinBackoff = 200 * time.Millisecond
	cfg.MaxBackoff = time.Minute
	cfg.Rand = func() float64 { return 0 }
	h.install(&cfg)
	delivered := make(chan struct{}, 8)
	startClient(t, t.Context(), cfg, func(context.Context, int, []byte) error {
		delivered <- struct{}{}
		return nil
	})

	recv(t, h.connects, "the connect")
	recv(t, delivered, "the one frame the peer sends before hanging up")
	require.Error(t, recv(t, h.disconnects, "the close that follows it"))
	r := recv(t, h.retries, "the wait before the redial")
	assert.Equal(t, cfg.MinBackoff, r.delay, "a frame on a short-lived connection is not proof")
	assert.Less(t, srv.upgrades.Load(), int32(10), "a paced loop cannot have run away")
}

// TestClient_ConcurrentWritesDuringReconnect keeps writers busy across a
// forced reconnect, so writes land on the old connection, in the gap, and on
// the new one. gorilla/websocket panics on two concurrent writers and a
// write racing the close corrupts frames, so this catches a lost write
// mutex without the race detector, which is what this repository's CI runs.
func TestClient_ConcurrentWritesDuringReconnect(t *testing.T) {
	const writers = 8
	srv := newBackhaulServer(t)
	h := newHooks()
	cfg := testConfig(srv.url)
	h.install(&cfg)
	c, _ := startClient(t, t.Context(), cfg, discard)
	recv(t, h.connects, "the first connect")
	first := recv(t, srv.accepted, "the first connection")

	stop := make(chan struct{})
	var sent, refused atomic.Int64
	var wg sync.WaitGroup
	// Registered before the writers start: an assertion below calls FailNow,
	// which would otherwise leave eight goroutines spinning on the write path
	// for the rest of the package's run.
	var stopOnce sync.Once
	halt := func() { stopOnce.Do(func() { close(stop) }); wg.Wait() }
	t.Cleanup(halt)
	for w := range writers {
		wg.Go(func() {
			for seq := 0; ; seq++ {
				select {
				case <-stop:
					return
				default:
				}
				if err := c.WriteJSON(map[string]int{"writer": w, "seq": seq}); err != nil {
					refused.Add(1)
					continue
				}
				sent.Add(1)
			}
		})
	}

	require.Eventually(t, func() bool { return first.frames.Load() > 0 },
		waitFor, time.Millisecond, "no write reached the first connection")
	c.Reconnect()
	second := recv(t, srv.accepted, "the connection Reconnect asked for")
	require.Eventually(t, func() bool { return second.frames.Load() > 0 },
		waitFor, time.Millisecond, "no write reached the connection dialed by Reconnect")
	halt()

	assert.Positive(t, sent.Load())
	for _, sc := range []*serverConn{first, second} {
		for drained := false; !drained; {
			select {
			case msg := <-sc.received:
				var body map[string]int
				assert.NoError(t, json.Unmarshal(msg, &body), "frame %q was corrupted", msg)
			default:
				drained = true
			}
		}
	}
}
