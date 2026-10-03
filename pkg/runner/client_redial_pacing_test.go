package runner

import (
	"bufio"
	"context"
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newDroppingServer accepts each WebSocket upgrade and closes the connection
// at once, recording when each one was accepted.
func newDroppingServer(t *testing.T) (url string, accepted func() []time.Time) {
	t.Helper()
	var mu sync.Mutex
	var at []time.Time
	url = newKeepaliveServer(t, func(int, *websocket.Conn) {
		mu.Lock()
		at = append(at, time.Now())
		mu.Unlock()
	})
	return url, func() []time.Time {
		mu.Lock()
		defer mu.Unlock()
		return append([]time.Time(nil), at...)
	}
}

// requireGrowingGaps waits for five connections and checks that the gap
// before each redial is at least the backoff step it should have waited:
// initial, then twice that, and so on.
func requireGrowingGaps(t *testing.T, accepted func() []time.Time, initial time.Duration) {
	t.Helper()
	require.Eventually(t, func() bool { return len(accepted()) >= 5 }, 10*time.Second, 10*time.Millisecond,
		"the client stopped redialling a server that drops every connection")

	at := accepted()
	for i := 1; i < 5; i++ {
		want := initial << (i - 1)
		assert.GreaterOrEqual(t, at[i].Sub(at[i-1]), want, "redial %d came before the backoff step %s", i, want)
	}
}

func TestRunForever_BacksOffWhenTheServerDropsEachConnectionAtOnce(t *testing.T) {
	url, accepted := newDroppingServer(t)
	useWSPath(t, url)

	a := newAuthBackoff(50*time.Millisecond, 5*time.Second)
	a.backoff.Rand = func() float64 { return 0.5 } // a factor of exactly 1: 50ms, 100ms, 200ms, 400ms
	wc := &WebsocketClient{connectBackoff: a}
	startRunForever(t, wc)

	requireGrowingGaps(t, accepted, 50*time.Millisecond)
}

func TestControlRunForever_BacksOffWhenTheServerDropsEachConnectionAtOnce(t *testing.T) {
	url, accepted := newDroppingServer(t)
	useControlWSPath(t, url)

	a := newAuthBackoff(50*time.Millisecond, 5*time.Second)
	a.backoff.Rand = func() float64 { return 0.5 }
	cc := &ControlClient{connectBackoff: a}
	startControlRunForever(t, cc)

	requireGrowingGaps(t, accepted, 50*time.Millisecond)
}

func TestRunForever_JittersTheRedialAfterAConnectionThatStayedUpDrops(t *testing.T) {
	shrinkKeepalive(t, time.Hour, time.Hour, 400*time.Millisecond)

	dropped := make(chan time.Time, 1)
	redialed := make(chan time.Time, 1)
	url := newKeepaliveServer(t, func(n int, c *websocket.Conn) {
		if n == 0 {
			dropped <- time.Now()
			return
		}
		if n == 1 {
			redialed <- time.Now()
		}
		_ = readUntilError(c)
	})
	useWSPath(t, url)

	a := newAuthBackoff(minConnectInterval, maxConnectInterval)
	a.rand = func() float64 { return 0.5 } // half of the 400ms jitter window
	// Each reading of the clock is a minute after the last, so every
	// connection looks like it stayed up past healthyUptime.
	var minutes atomic.Int64
	start := time.Now()
	a.now = func() time.Time { return start.Add(time.Duration(minutes.Add(1)) * time.Minute) }
	wc := &WebsocketClient{connectBackoff: a}
	startRunForever(t, wc)

	var droppedAt, redialedAt time.Time
	select {
	case droppedAt = <-dropped:
	case <-time.After(5 * time.Second):
		t.Fatal("the first connection was never made")
	}
	select {
	case redialedAt = <-redialed:
	case <-time.After(5 * time.Second):
		t.Fatal("the client never redialled after the connection dropped")
	}

	gap := redialedAt.Sub(droppedAt)
	assert.GreaterOrEqual(t, gap, 200*time.Millisecond, "the redial after a dropped connection was not jittered")
	assert.Less(t, gap, minConnectInterval, "a connection that stayed up was paced by the backoff instead of the jitter")
}

// dialPeerThatNeverReads returns a client connection over an in-memory pipe
// whose far end completes the WebSocket handshake and then never reads, so
// every write on it blocks until its deadline.
func dialPeerThatNeverReads(t *testing.T) (*websocket.Conn, *trackedConn) {
	t.Helper()
	client, server := net.Pipe()
	tracked := &trackedConn{Conn: client}
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})

	go func() {
		req, err := http.ReadRequest(bufio.NewReader(server))
		if err != nil {
			return
		}
		sum := sha1.Sum([]byte(req.Header.Get("Sec-WebSocket-Key") + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
		_, _ = fmt.Fprintf(server, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n",
			base64.StdEncoding.EncodeToString(sum[:]))
	}()

	dialer := websocket.Dialer{
		NetDialContext: func(context.Context, string, string) (net.Conn, error) { return tracked, nil },
	}
	conn, _, err := dialer.Dial("ws://peer.test/", nil)
	require.NoError(t, err)
	return conn, tracked
}

// requireWriteTimesOut runs write against a peer that never reads and checks
// that it fails with a timeout and closes the connection, so the read loop
// reconnects.
func requireWriteTimesOut(t *testing.T, write func(conn *websocket.Conn) error) {
	synctest.Test(t, func(t *testing.T) {
		conn, tracked := dialPeerThatNeverReads(t)

		done := make(chan error, 1)
		go func() { done <- write(conn) }()

		var err error
		select {
		case err = <-done:
		case <-time.After(time.Minute):
			t.Fatal("WriteJSON was still blocked a minute after the peer stopped reading")
		}

		var netErr net.Error
		require.True(t, errors.As(err, &netErr) && netErr.Timeout(), "WriteJSON returned %v, not a timeout", err)
		assert.True(t, tracked.closed.Load(), "a timed-out write left the connection open for the read loop")
	})
}

func TestWriteJSON_TimesOutOnAPeerThatNeverReads(t *testing.T) {
	requireWriteTimesOut(t, func(conn *websocket.Conn) error {
		wc := &WebsocketClient{Conn: conn}
		return wc.WriteJSON(map[string]string{"query": "pong"})
	})
}

func TestControlWriteJSON_TimesOutOnAPeerThatNeverReads(t *testing.T) {
	requireWriteTimesOut(t, func(conn *websocket.Conn) error {
		cc := &ControlClient{Conn: conn}
		return cc.WriteJSON(map[string]string{"query": "pong"})
	})
}
