package runner

// The websocket test conn lives here, untagged, so close tests that have no Unix-specific behavior stay in the Windows CI job.

import (
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/require"
)

// trackedConn fails writes on demand, so a test can play out a broken connection without breaking a real one.
type trackedConn struct {
	net.Conn
	failWrites    atomic.Bool
	closed        atomic.Bool
	readDeadlines atomic.Int32
	onWrite       func() // set before the write under test, and only from the goroutine that drives it
}

func (c *trackedConn) SetReadDeadline(t time.Time) error {
	c.readDeadlines.Add(1)
	return c.Conn.SetReadDeadline(t)
}

func (c *trackedConn) Write(b []byte) (int, error) {
	if c.onWrite != nil {
		c.onWrite()
	}
	if c.failWrites.Load() {
		return 0, errors.New("simulated write failure")
	}
	return c.Conn.Write(b)
}

func (c *trackedConn) Close() error {
	c.closed.Store(true)
	return c.Conn.Close()
}

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
