package runner

// The backhaul mirror of the pty client's close tests in pty_recovery_test.go; keep the two in step.

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
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

func TestWebsocketClientClose_DrainsReplyAfterSuccessfulHandshake(t *testing.T) {
	s := newCloseReplyServer(t)
	conn, tracked := dialTracked(t, s.url)

	wc := &WebsocketClient{Conn: conn}

	deadlines := tracked.readDeadlines.Load()
	wc.Close()

	require.Equal(t, int32(websocket.CloseNormalClosure), s.closeCode.Load(), "the peer did not receive a normal-closure close frame")
	require.Greater(t, tracked.readDeadlines.Load(), deadlines, "Close() skipped the drain even though the close frame went out")
	require.True(t, tracked.closed.Load(), "Close() did not close the websocket connection after a successful handshake")
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
