package runner

import (
	"io"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateTargetAddr(t *testing.T) {
	tests := []struct {
		name       string
		targetAddr string
		want       bool
	}{
		{name: "allow localhost ip", targetAddr: "127.0.0.1:8080", want: true},
		{name: "allow localhost hostname", targetAddr: "localhost:3000", want: true},
		{name: "allow localhost hostname any case", targetAddr: "LocalHost:3000", want: true},
		{name: "allow ipv6 loopback", targetAddr: "[::1]:8080", want: true},
		{name: "allow loopback range", targetAddr: "127.0.0.53:53", want: true},
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
			if got != tc.want {
				t.Fatalf("validateTargetAddr(%q) = %v, want %v", tc.targetAddr, got, tc.want)
			}
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

func TestDialDirect(t *testing.T) {
	t.Run("rejects non-loopback without dialing", func(t *testing.T) {
		for _, addr := range []string{"10.0.0.1:80", "example.com:80", "127.0.0.1"} {
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
