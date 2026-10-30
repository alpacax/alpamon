package runner

import (
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateTargetAddr(t *testing.T) {
	tests := []struct {
		name       string
		targetAddr string
		want       bool
	}{
		{name: "allow loopback ip", targetAddr: "127.0.0.1:8080", want: true},
		{name: "allow ipv6 loopback", targetAddr: "[::1]:8080", want: true},
		{name: "allow loopback range", targetAddr: "127.0.0.53:53", want: true},
		{name: "reject localhost name", targetAddr: "localhost:3000", want: false},
		{name: "reject missing port", targetAddr: "127.0.0.1", want: false},
		{name: "reject host merely starting with loopback", targetAddr: "127.0.0.1.evil.example:80", want: false},
		{name: "reject all interfaces", targetAddr: "0.0.0.0:80", want: false},
		{name: "reject private network ip", targetAddr: "192.168.0.10:22", want: false},
		{name: "reject external hostname", targetAddr: "example.com:443", want: false},
		{name: "reject empty string", targetAddr: "", want: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := validateTargetAddr(tc.targetAddr)
			require.Equal(t, tc.want, got, "validateTargetAddr(%q)", tc.targetAddr)
		})
	}
}

func acceptOne(t *testing.T, ln net.Listener) <-chan net.Conn {
	t.Helper()
	ch := make(chan net.Conn, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			close(ch)
			return
		}
		ch <- conn
	}()
	return ch
}

// tcpPair returns both ends of a loopback TCP connection, which supports CloseWrite.
func tcpPair(t *testing.T) (*net.TCPConn, *net.TCPConn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = ln.Close() }()
	serverCh := acceptOne(t, ln)

	client, err := net.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)
	server := <-serverCh
	require.NotNil(t, server)
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})
	return client.(*net.TCPConn), server.(*net.TCPConn)
}

// readAllWithin reads conn to EOF, failing instead of hanging when the relay never ends it.
func readAllWithin(t *testing.T, conn net.Conn) string {
	t.Helper()
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(5*time.Second)))
	data, err := io.ReadAll(conn)
	require.NoError(t, err)
	return string(data)
}

func waitRelayDone(t *testing.T, done <-chan struct{}, within time.Duration) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(within):
		t.Fatal("relay did not return")
	}
}

// startDaemonRelay runs handleDaemonConnection as the daemon would and returns the main
// process's end of the connection, the target's accepted connection, and a done channel.
func startDaemonRelay(t *testing.T) (*net.TCPConn, net.Conn, <-chan struct{}) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	targetCh := acceptOne(t, ln)

	mainSide, daemonSide := tcpPair(t)
	var wg sync.WaitGroup
	wg.Add(1)
	done := make(chan struct{})
	go func() {
		handleDaemonConnection(daemonSide, &wg)
		close(done)
	}()

	_, err = mainSide.Write([]byte(ln.Addr().String() + "\n"))
	require.NoError(t, err)
	target := <-targetCh
	require.NotNil(t, target)
	t.Cleanup(func() { _ = target.Close() })
	return mainSide, target, done
}

func TestHandleDaemonConnectionDeliversResponseAfterMainHalfCloses(t *testing.T) {
	mainSide, target, done := startDaemonRelay(t)

	_, err := mainSide.Write([]byte("request"))
	require.NoError(t, err)
	require.NoError(t, mainSide.CloseWrite())
	assert.Equal(t, "request", readAllWithin(t, target))

	_, err = target.Write([]byte("response"))
	require.NoError(t, err)
	require.NoError(t, target.(*net.TCPConn).CloseWrite())

	assert.Equal(t, "response", readAllWithin(t, mainSide))
	waitRelayDone(t, done, 5*time.Second)
}

func TestHandleDaemonConnectionCarriesMainDataAfterTargetHalfCloses(t *testing.T) {
	mainSide, target, done := startDaemonRelay(t)

	_, err := target.Write([]byte("banner"))
	require.NoError(t, err)
	require.NoError(t, target.(*net.TCPConn).CloseWrite())
	assert.Equal(t, "banner", readAllWithin(t, mainSide))

	_, err = mainSide.Write([]byte("late"))
	require.NoError(t, err)
	require.NoError(t, mainSide.CloseWrite())

	assert.Equal(t, "late", readAllWithin(t, target))
	waitRelayDone(t, done, 5*time.Second)
}

func TestDialDirect(t *testing.T) {
	t.Run("rejects invalid targets without dialing", func(t *testing.T) {
		for _, addr := range []string{"10.0.0.1:80", "example.com:80", "localhost:80", "127.0.0.1"} {
			conn, err := dialDirect(addr)
			require.Error(t, err, addr)
			assert.Nil(t, conn, addr)
			assert.Contains(t, err.Error(), "invalid target address", addr)
		}
	})

	t.Run("dials a localhost listener and relays bytes", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		defer func() { _ = ln.Close() }()
		serverCh := acceptOne(t, ln)

		conn, err := dialDirect(ln.Addr().String())
		require.NoError(t, err)
		defer func() { _ = conn.Close() }()

		// TCP tuning requires a *net.TCPConn; the half-close path relies on it too.
		require.IsType(t, &net.TCPConn{}, conn)

		server := <-serverCh
		require.NotNil(t, server)
		defer func() { _ = server.Close() }()

		_, err = conn.Write([]byte("ping"))
		require.NoError(t, err)
		buf := make([]byte, 4)
		_, err = io.ReadFull(server, buf)
		require.NoError(t, err)
		assert.Equal(t, "ping", string(buf))
	})
}
