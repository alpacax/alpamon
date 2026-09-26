package runner

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/alpacax/alpamon/v2/pkg/config"
	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const keepaliveTimeoutLog = "No response from Alpacon for 2 minutes; reconnecting."

// shrinkKeepalive swaps in short keepalive timings. Register it before
// starting RunForever, so its cleanup runs after the loop has stopped.
func shrinkKeepalive(t *testing.T, interval, timeout, jitter time.Duration) {
	t.Helper()
	origInterval, origTimeout, origJitter := keepaliveInterval, keepaliveTimeout, keepaliveRedialJitter
	keepaliveInterval, keepaliveTimeout, keepaliveRedialJitter = interval, timeout, jitter
	t.Cleanup(func() {
		keepaliveInterval, keepaliveTimeout, keepaliveRedialJitter = origInterval, origTimeout, origJitter
	})
}

func useWSPath(t *testing.T, url string) {
	t.Helper()
	orig := config.GlobalSettings.WSPath
	config.GlobalSettings.WSPath = url
	t.Cleanup(func() { config.GlobalSettings.WSPath = orig })
}

// newKeepaliveServer runs handle for each accepted connection, numbered from 0.
func newKeepaliveServer(t *testing.T, handle func(n int, c *websocket.Conn)) string {
	t.Helper()
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	var next atomic.Int32

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer func() { _ = c.Close() }()
		handle(int(next.Add(1)-1), c)
	}))
	t.Cleanup(ts.Close)

	return strings.Replace(ts.URL, "http", "ws", 1)
}

func readUntilError(c *websocket.Conn) error {
	for {
		if _, _, err := c.ReadMessage(); err != nil {
			return err
		}
	}
}

// startRunForever runs the read loop and returns a stop that cancels it and
// closes the connection, as gracefulShutdown does, then waits for it to return.
func startRunForever(t *testing.T, wc *WebsocketClient) (stop func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		wc.RunForever(ctx)
	}()

	stop = sync.OnceFunc(func() {
		cancel()
		wc.Close()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("RunForever did not return after cancel and Close")
		}
	})
	t.Cleanup(stop)
	return stop
}

// deadlineConn records how far ahead each read deadline was armed.
type deadlineConn struct {
	net.Conn
	mu   sync.Mutex
	left []time.Duration
}

func (c *deadlineConn) SetReadDeadline(t time.Time) error {
	if !t.IsZero() {
		c.mu.Lock()
		c.left = append(c.left, time.Until(t))
		c.mu.Unlock()
	}
	return c.Conn.SetReadDeadline(t)
}

func (c *deadlineConn) armed() []time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]time.Duration(nil), c.left...)
}

// dialRecording dials like dialWebsocket but hands each socket to conns first.
func dialRecording(conns chan<- *deadlineConn) func(context.Context, string, http.Header) (*websocket.Conn, error) {
	return func(ctx context.Context, url string, header http.Header) (*websocket.Conn, error) {
		dialer := websocket.Dialer{
			NetDialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				c, err := (&net.Dialer{}).DialContext(ctx, network, addr)
				if err != nil {
					return nil, err
				}
				dc := &deadlineConn{Conn: c}
				conns <- dc
				return dc, nil
			},
		}
		conn, _, err := dialer.DialContext(ctx, url, header)
		return conn, err
	}
}

func TestRunForever_RedialsAPeerThatStopsAnsweringPings(t *testing.T) {
	// Production timings divided by 100, so the issue's 150 s bound becomes 1.5 s.
	shrinkKeepalive(t, 300*time.Millisecond, 1200*time.Millisecond, 100*time.Millisecond)
	const redialBound = 1500 * time.Millisecond

	silentAt := make(chan time.Time, 1)
	resume := make(chan struct{})
	releaseResume := sync.OnceFunc(func() { close(resume) })
	t.Cleanup(releaseResume)
	firstReadEnd := make(chan error, 1)
	var closeFrame atomic.Bool
	redialAt := make(chan time.Time, 1)

	url := newKeepaliveServer(t, func(n int, c *websocket.Conn) {
		if n > 0 {
			redialAt <- time.Now()
			_ = readUntilError(c)
			return
		}

		// Answer the first ping, then stop reading altogether: the socket
		// stays up but nothing comes back, as on a silently dropped link.
		answered := false
		c.SetPingHandler(func(data string) error {
			if answered {
				return nil
			}
			answered = true
			_ = c.WriteControl(websocket.PongMessage, []byte(data), time.Now().Add(time.Second))
			silentAt <- time.Now()
			<-resume
			return nil
		})
		c.SetCloseHandler(func(int, string) error {
			closeFrame.Store(true)
			return nil
		})
		firstReadEnd <- readUntilError(c)
	})
	useWSPath(t, url)
	logs := captureLogs(t)

	wc := &WebsocketClient{connectBackoff: newAuthBackoff(minConnectInterval, maxConnectInterval)}
	stop := startRunForever(t, wc)

	var silent, redial time.Time
	select {
	case silent = <-silentAt:
	case <-time.After(5 * time.Second):
		t.Fatal("the client never pinged the server")
	}
	select {
	case redial = <-redialAt:
	case <-time.After(5 * time.Second):
		t.Fatal("the client never redialled after the server went silent")
	}

	elapsed := redial.Sub(silent)
	assert.LessOrEqual(t, elapsed, redialBound, "the redial came later than keepaliveTimeout plus the redial jitter")
	assert.GreaterOrEqual(t, elapsed, keepaliveTimeout*3/4, "the client redialled before keepaliveTimeout had run out")

	// Let the silent side read what the client left behind: its pings, then the end of the socket.
	releaseResume()
	var readErr error
	select {
	case readErr = <-firstReadEnd:
	case <-time.After(5 * time.Second):
		t.Fatal("the dropped connection was never closed")
	}
	assert.False(t, closeFrame.Load(), "the client sent a close frame on a keepalive timeout")
	var closeErr *websocket.CloseError
	if errors.As(readErr, &closeErr) {
		assert.Equal(t, websocket.CloseAbnormalClosure, closeErr.Code, "the dropped connection did not end without a close frame")
	}

	stop()
	assert.Equal(t, 1, strings.Count(logs.String(), keepaliveTimeoutLog), "the keepalive timeout should be logged exactly once")
}

func TestRunForever_KeepsAConnectionWhosePeerAnswersPings(t *testing.T) {
	shrinkKeepalive(t, 50*time.Millisecond, 400*time.Millisecond, 10*time.Millisecond)

	var connections, pings atomic.Int32
	url := newKeepaliveServer(t, func(_ int, c *websocket.Conn) {
		connections.Add(1)
		c.SetPingHandler(func(data string) error {
			pings.Add(1)
			return c.WriteControl(websocket.PongMessage, []byte(data), time.Now().Add(time.Second))
		})
		_ = readUntilError(c)
	})
	useWSPath(t, url)

	conns := make(chan *deadlineConn, 4)
	wc := &WebsocketClient{
		connectBackoff: newAuthBackoff(minConnectInterval, maxConnectInterval),
		dial:           dialRecording(conns),
	}
	stop := startRunForever(t, wc)

	// No data frame is ever sent: only pongs can keep the deadline moving,
	// for five times keepaliveTimeout.
	time.Sleep(5 * keepaliveTimeout)

	_, ka := wc.connState()
	require.NotNil(t, ka)
	assert.True(t, ka.pongSeen.Load(), "no pong was recorded")
	assert.Equal(t, int32(1), connections.Load(), "the connection dropped although the peer answered every ping")
	assert.GreaterOrEqual(t, pings.Load(), int32(10), "the client did not keep pinging")

	stop()
	require.Len(t, conns, 1)
	armed := (<-conns).armed()
	require.NotEmpty(t, armed)
	assert.LessOrEqual(t, armed[len(armed)-1], keepaliveTimeout, "the deadline was not shortened after the peer answered a ping")
}

func TestRunForever_KeepsTheLongDeadlineForAPeerThatNeverAnswersPings(t *testing.T) {
	shrinkKeepalive(t, 20*time.Millisecond, 100*time.Millisecond, 10*time.Millisecond)

	var connections, pings atomic.Int32
	url := newKeepaliveServer(t, func(_ int, c *websocket.Conn) {
		connections.Add(1)
		c.SetPingHandler(func(string) error {
			pings.Add(1)
			return nil // never answers
		})
		go func() {
			// Empty frames make the read loop arm a fresh deadline without side effects.
			for range 3 {
				time.Sleep(150 * time.Millisecond)
				if err := c.WriteMessage(websocket.TextMessage, nil); err != nil {
					return
				}
			}
		}()
		_ = readUntilError(c)
	})
	useWSPath(t, url)

	conns := make(chan *deadlineConn, 4)
	wc := &WebsocketClient{
		connectBackoff: newAuthBackoff(minConnectInterval, maxConnectInterval),
		dial:           dialRecording(conns),
	}
	stop := startRunForever(t, wc)

	time.Sleep(10 * keepaliveTimeout)

	_, ka := wc.connState()
	require.NotNil(t, ka)
	assert.False(t, ka.pongSeen.Load())
	assert.Equal(t, int32(1), connections.Load(), "the connection dropped although no keepalive deadline applies to this peer")
	assert.GreaterOrEqual(t, pings.Load(), int32(5), "the client did not keep pinging")

	stop()
	require.Len(t, conns, 1)
	armed := (<-conns).armed()
	// The first read, then one per empty frame.
	require.GreaterOrEqual(t, len(armed), 4)
	for i, left := range armed {
		assert.Greater(t, left, ConnectionReadTimeout-time.Minute, "read deadline %d was not ConnectionReadTimeout", i)
	}
}

func TestRunForever_WriteJSONAlongsideKeepalivePings(t *testing.T) {
	// Run with -race: the keepalive goroutine's WriteControl, the pong
	// handler on the read loop and WriteJSON all touch the same connection.
	shrinkKeepalive(t, time.Millisecond, time.Second, 10*time.Millisecond)
	const messages = 200

	var data, pings atomic.Int32
	connected := make(chan struct{}, 1)
	url := newKeepaliveServer(t, func(_ int, c *websocket.Conn) {
		c.SetPingHandler(func(appData string) error {
			pings.Add(1)
			return c.WriteControl(websocket.PongMessage, []byte(appData), time.Now().Add(time.Second))
		})
		connected <- struct{}{}
		for {
			if _, _, err := c.ReadMessage(); err != nil {
				return
			}
			data.Add(1)
		}
	})
	useWSPath(t, url)

	wc := &WebsocketClient{connectBackoff: newAuthBackoff(minConnectInterval, maxConnectInterval)}
	stop := startRunForever(t, wc)

	select {
	case <-connected:
	case <-time.After(5 * time.Second):
		t.Fatal("the client never connected")
	}
	require.Eventually(t, func() bool { return wc.conn() != nil }, 5*time.Second, time.Millisecond)

	for i := range messages {
		require.NoError(t, wc.WriteJSON(map[string]int{"seq": i}))
	}

	require.Eventually(t, func() bool { return data.Load() == messages }, 5*time.Second, time.Millisecond,
		"the server did not receive every JSON frame")
	assert.Positive(t, pings.Load(), "no ping went out while WriteJSON was writing")

	stop()
}

func TestSendPings_StopsOnceTheConnectionIsReplaced(t *testing.T) {
	var pings atomic.Int32
	url := newKeepaliveServer(t, func(_ int, c *websocket.Conn) {
		c.SetPingHandler(func(string) error {
			pings.Add(1)
			return nil
		})
		_ = readUntilError(c)
	})
	first, _ := dialTracked(t, url)
	second, _ := dialTracked(t, url)
	t.Cleanup(func() { _ = first.Close(); _ = second.Close() })

	wc := &WebsocketClient{Conn: first}
	done := make(chan struct{})
	go func() {
		defer close(done)
		wc.sendPings(context.Background(), first, newConnKeepalive(), time.Millisecond)
	}()

	require.Eventually(t, func() bool { return pings.Load() >= 2 }, 5*time.Second, time.Millisecond,
		"the current connection was not pinged")

	wc.swapConn(second)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("sendPings kept running for a connection that is no longer current")
	}
}

func TestSendPings_StopsOnceTheConnectionIsClosed(t *testing.T) {
	// Close leaves Conn in place and the context may outlive it, so neither of the other exits fires.
	var pings atomic.Int32
	url := newKeepaliveServer(t, func(_ int, c *websocket.Conn) {
		c.SetPingHandler(func(string) error {
			pings.Add(1)
			return nil
		})
		_ = readUntilError(c)
	})
	conn, _ := dialTracked(t, url)

	ka := newConnKeepalive()
	wc := &WebsocketClient{}
	wc.installConn(conn, ka)
	done := make(chan struct{})
	go func() {
		defer close(done)
		wc.sendPings(context.Background(), conn, ka, time.Millisecond)
	}()

	require.Eventually(t, func() bool { return pings.Load() >= 2 }, 5*time.Second, time.Millisecond,
		"the current connection was not pinged")

	wc.Close()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("sendPings kept running for a connection Close had closed")
	}
	assert.Same(t, conn, wc.conn(), "Close is expected to leave Conn in place")
}

func TestConnect_OutsideRunForeverDoesNotPing(t *testing.T) {
	// pkg/pluginclient calls Connect from its own read loop, which does not act on a keepalive timeout.
	shrinkKeepalive(t, time.Millisecond, 10*time.Millisecond, time.Millisecond)

	var pings atomic.Int32
	url := newKeepaliveServer(t, func(_ int, c *websocket.Conn) {
		c.SetPingHandler(func(string) error {
			pings.Add(1)
			return nil
		})
		_ = readUntilError(c)
	})
	useWSPath(t, url)

	wc := &WebsocketClient{connectBackoff: newAuthBackoff(minConnectInterval, maxConnectInterval)}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	require.NoError(t, wc.Connect(ctx))
	t.Cleanup(wc.Close)

	time.Sleep(50 * time.Millisecond)

	_, ka := wc.connState()
	assert.Nil(t, ka, "Connect set up keepalive for a read loop that is not RunForever")
	assert.Zero(t, pings.Load(), "Connect pinged a connection whose read loop is not RunForever")
}

func TestSendPings_KeepsGoingAfterAFailedPing(t *testing.T) {
	url := newKeepaliveServer(t, func(_ int, c *websocket.Conn) { _ = readUntilError(c) })
	conn, tracked := dialTracked(t, url)
	t.Cleanup(func() { _ = conn.Close() })
	tracked.failWrites.Store(true)

	wc := &WebsocketClient{Conn: conn}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		wc.sendPings(ctx, conn, newConnKeepalive(), time.Millisecond)
	}()

	// A failed ping is the read deadline's to act on, not a reason to stop pinging.
	select {
	case <-done:
		t.Fatal("sendPings stopped on a failed ping while the connection was still current")
	case <-time.After(50 * time.Millisecond):
	}

	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("sendPings did not stop when the context ended")
	}
}

func TestConnKeepalive_ReadTimeoutFollowsTheFirstPong(t *testing.T) {
	var nilKeepalive *connKeepalive
	assert.Equal(t, ConnectionReadTimeout, nilKeepalive.readTimeout(), "a connection Connect did not install keeps the long deadline")

	ka := &connKeepalive{}
	assert.Equal(t, ConnectionReadTimeout, ka.readTimeout(), "no pong yet, so the long deadline stays")

	ka.pongSeen.Store(true)
	assert.Equal(t, keepaliveTimeout, ka.readTimeout())
}

func TestConnKeepalive_ExpiredOnlyForATimeoutAfterAPong(t *testing.T) {
	timeout := &net.OpError{Op: "read", Err: os.ErrDeadlineExceeded}

	var nilKeepalive *connKeepalive
	assert.False(t, nilKeepalive.expired(timeout))

	ka := &connKeepalive{}
	assert.False(t, ka.expired(timeout), "a peer that never answered a ping keeps today's reconnect path")

	ka.pongSeen.Store(true)
	assert.True(t, ka.expired(timeout))
	assert.False(t, ka.expired(&websocket.CloseError{Code: websocket.CloseGoingAway}), "a close is not a keepalive timeout")
	assert.False(t, ka.expired(net.ErrClosed))
}

func TestAuthBackoff_RedialJitterSpansZeroToTheCap(t *testing.T) {
	a := newAuthBackoff(minConnectInterval, maxConnectInterval)

	a.rand = func() float64 { return 0 }
	assert.Equal(t, time.Duration(0), a.redialJitter())

	a.rand = func() float64 { return 0.5 }
	assert.Equal(t, keepaliveRedialJitter/2, a.redialJitter())

	a.rand = func() float64 { return 0.999 }
	assert.Less(t, a.redialJitter(), keepaliveRedialJitter)
}

func TestAuthBackoff_WaitBeforeRedial(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		a := newAuthBackoff(minConnectInterval, maxConnectInterval)
		a.rand = func() float64 { return 0.5 }

		start := time.Now()
		require.NoError(t, a.waitBeforeRedial(context.Background()))
		assert.Equal(t, keepaliveRedialJitter/2, time.Since(start))
	})

	synctest.Test(t, func(t *testing.T) {
		a := newAuthBackoff(minConnectInterval, maxConnectInterval)
		a.rand = func() float64 { return 0.5 }
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		start := time.Now()
		require.ErrorIs(t, a.waitBeforeRedial(ctx), context.Canceled)
		assert.Zero(t, time.Since(start), "a cancelled context should not wait out the jitter")
	})
}
