package runner

import (
	"io"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// acceptOne accepts a single connection from ln and returns it via the channel.
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

func TestDialDirect(t *testing.T) {
	t.Run("rejects non-localhost without dialing", func(t *testing.T) {
		for _, addr := range []string{"10.0.0.1:80", "example.com:80", "[::1]:80"} {
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

func TestCloseWriteSide(t *testing.T) {
	t.Run("tcp conn delivers EOF but keeps read side open", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		defer func() { _ = ln.Close() }()
		serverCh := acceptOne(t, ln)

		client, err := net.Dial("tcp", ln.Addr().String())
		require.NoError(t, err)
		defer func() { _ = client.Close() }()

		server := <-serverCh
		require.NotNil(t, server)
		defer func() { _ = server.Close() }()

		closeWriteSide(client)

		// Server sees EOF on read...
		buf := make([]byte, 1)
		_, err = server.Read(buf)
		assert.Equal(t, io.EOF, err)

		// ...but the reverse direction still works.
		_, err = server.Write([]byte("x"))
		require.NoError(t, err)
		n, err := client.Read(buf)
		require.NoError(t, err)
		assert.Equal(t, 1, n)
		assert.Equal(t, byte('x'), buf[0])
	})

	t.Run("conn without CloseWrite is a safe no-op", func(t *testing.T) {
		a, b := net.Pipe()
		defer func() { _ = a.Close() }()
		defer func() { _ = b.Close() }()

		assert.NotPanics(t, func() { closeWriteSide(a) })
	})
}
