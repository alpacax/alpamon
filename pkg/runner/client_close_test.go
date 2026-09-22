package runner

// The backhaul mirror of the pty client's close tests in pty_recovery_test.go; keep the two in step.

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// closeReplyServer answers the client's close frame; the pty test double never reads, so a drain against it would only end on the read deadline.
type closeReplyServer struct {
	url       string
	closeCode atomic.Int32
}

func newCloseReplyServer(t *testing.T) *closeReplyServer {
	t.Helper()
	s := &closeReplyServer{}
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer func() { _ = c.Close() }()

		c.SetCloseHandler(func(code int, text string) error {
			s.closeCode.Store(int32(code))
			// SetCloseHandler replaces gorilla's default reply; without this the client drains until its deadline.
			_ = c.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(code, ""), time.Now().Add(time.Second))
			return nil
		})

		for {
			if _, _, err := c.ReadMessage(); err != nil {
				return
			}
		}
	}))
	t.Cleanup(ts.Close)

	s.url = strings.Replace(ts.URL, "http", "ws", 1)
	return s
}

func TestWebsocketClientClose_ClosesConnAfterWriteControlFailure(t *testing.T) {
	s := newCloseReplyServer(t)
	conn, tracked := dialTracked(t, s.url)

	wc := &WebsocketClient{Conn: conn}

	deadlines := tracked.readDeadlines.Load()
	tracked.failWrites.Store(true)
	wc.Close()

	require.True(t, tracked.closed.Load(), "Close() did not close the websocket connection after WriteControl failure")
	require.Equal(t, deadlines, tracked.readDeadlines.Load(), "Close() waited for a close reply the peer can never send, because the close frame never went out")
}

func TestWebsocketClientClose_DoesNotDrainBecauseTheReadLoopOwnsReads(t *testing.T) {
	// gorilla allows one reader; Close() can run while the loop is inside ReadMessage.
	s := newCloseReplyServer(t)
	conn, tracked := dialTracked(t, s.url)

	wc := &WebsocketClient{Conn: conn}

	deadlines := tracked.readDeadlines.Load()
	wc.Close()

	// Close() does not wait for the peer, so give the server goroutine a moment to process the frame it already received.
	require.Eventually(t, func() bool {
		return s.closeCode.Load() == int32(websocket.CloseNormalClosure)
	}, time.Second, time.Millisecond, "the peer did not receive a normal-closure close frame")
	assert.Equal(t, deadlines, tracked.readDeadlines.Load(), "Close() drained the reply even though it does not own the reads")
	assert.True(t, tracked.closed.Load(), "Close() did not close the websocket connection")
}

func TestWebsocketClientCloseAndDrain_DrainsReplyAfterSuccessfulHandshake(t *testing.T) {
	s := newCloseReplyServer(t)
	conn, tracked := dialTracked(t, s.url)

	wc := &WebsocketClient{Conn: conn}

	deadlines := tracked.readDeadlines.Load()
	wc.closeAndDrain()

	require.Equal(t, int32(websocket.CloseNormalClosure), s.closeCode.Load(), "the peer did not receive a normal-closure close frame")
	assert.Greater(t, tracked.readDeadlines.Load(), deadlines, "closeAndDrain() skipped the drain even though the close frame went out")
	assert.True(t, tracked.closed.Load(), "closeAndDrain() did not close the websocket connection")
}

func TestWebsocketClientClose_IsSafeToCallTwice(t *testing.T) {
	// Close() deliberately leaves wc.Conn in place: the reconnect handler closes it, then RunForever's next read failure sends CloseAndReconnect at the same conn.
	s := newCloseReplyServer(t)
	conn, tracked := dialTracked(t, s.url)

	wc := &WebsocketClient{Conn: conn}

	wc.Close()
	require.True(t, tracked.closed.Load(), "the first Close() did not close the websocket connection")
	require.NotPanics(t, wc.Close, "the second Close() on an already closed connection panicked")
}

func TestWebsocketClientClose_ClosesTheConnItStartedWith(t *testing.T) {
	// Connect() writes wc.Conn from the RunForever goroutine while Close() runs on another; the field swap is played out here from inside the close-frame write.
	s := newCloseReplyServer(t)
	first, firstTracked := dialTracked(t, s.url)
	second, secondTracked := dialTracked(t, s.url)
	t.Cleanup(func() { _ = second.Close() })

	wc := &WebsocketClient{Conn: first}
	firstTracked.onWrite = func() { wc.swapConn(second) }

	wc.Close()

	require.True(t, firstTracked.closed.Load(), "Close() left the connection it started with open")
	require.False(t, secondTracked.closed.Load(), "Close() closed the connection Connect() had just swapped in")
}

func TestWebsocketClientClose_IsRaceFreeAgainstTheReadLoop(t *testing.T) {
	// The loop writes conn through Connect while another goroutine reads it in Close; the real
	// guard against a broken mu is the race detector (run with -race), not this assertion alone.
	s := newCloseReplyServer(t)
	first, _ := dialTracked(t, s.url)
	second, _ := dialTracked(t, s.url)
	t.Cleanup(func() { _ = second.Close() })

	wc := &WebsocketClient{Conn: first}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); wc.swapConn(second) }()
	go func() { defer wg.Done(); wc.Close() }()
	wg.Wait()

	assert.Same(t, second, wc.conn(), "swapConn is the only writer left, so the conn must be second")
}
