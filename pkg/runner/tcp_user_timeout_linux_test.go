package runner

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func TestDialWebsocket_BoundsUnacknowledgedSends(t *testing.T) {
	// Given a WebSocket server
	upgrader := websocket.Upgrader{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		_, _, _ = conn.ReadMessage()
	}))
	defer server.Close()

	// When the agent dials it
	conn, err := dialWebsocket(t.Context(), "ws"+strings.TrimPrefix(server.URL, "http"), nil)
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()

	// Then the socket gives up on unacknowledged data after tcpUserTimeout, not tcp_retries2
	raw, err := conn.UnderlyingConn().(*net.TCPConn).SyscallConn()
	require.NoError(t, err)
	var got int
	var sockErr error
	require.NoError(t, raw.Control(func(fd uintptr) {
		got, sockErr = unix.GetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_USER_TIMEOUT)
	}))
	require.NoError(t, sockErr)
	assert.Equal(t, int(tcpUserTimeout.Milliseconds()), got)
}
