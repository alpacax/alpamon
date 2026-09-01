//go:build !windows

package runner

// The backhaul mirror of the pty client's close tests in pty_recovery_test.go; keep the two in step.

import (
	"net"
	"testing"

	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/require"
)

func dialTracked(t *testing.T, url string) (*websocket.Conn, *trackedConn) {
	t.Helper()

	var tracked *trackedConn
	dialer := websocket.Dialer{
		NetDial: func(network, addr string) (net.Conn, error) {
			c, err := net.Dial(network, addr)
			if err != nil {
				return nil, err
			}
			tracked = &trackedConn{Conn: c}
			return tracked, nil
		},
	}
	conn, _, err := dialer.Dial(url, nil)
	require.NoError(t, err)
	require.NotNil(t, tracked, "the dialer never went through NetDial, so nothing is being tracked")

	return conn, tracked
}

func TestWebsocketClientClose_ClosesConnAfterWriteControlFailure(t *testing.T) {
	s := newWshServer(t)
	conn, tracked := dialTracked(t, s.wsURL())

	wc := &WebsocketClient{Conn: conn}

	deadlines := tracked.readDeadlines.Load()
	tracked.failWrites.Store(true)
	wc.Close()

	require.True(t, tracked.closed.Load(), "Close() did not close the websocket connection after WriteControl failure")
	require.Equal(t, deadlines, tracked.readDeadlines.Load(), "Close() waited for a close reply the peer can never send, because the close frame never went out")
}
