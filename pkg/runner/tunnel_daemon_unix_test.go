//go:build !windows

package runner

import (
	"net"
	"os"
	"sync"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// unixPair returns both ends of a connected Unix stream socket, the kind the daemon accepts.
func unixPair(t *testing.T) (*net.UnixConn, *net.UnixConn) {
	t.Helper()
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	require.NoError(t, err)
	conns := make([]*net.UnixConn, 2)
	for i, fd := range fds {
		f := os.NewFile(uintptr(fd), "")
		conn, err := net.FileConn(f)
		_ = f.Close()
		require.NoError(t, err)
		t.Cleanup(func() { _ = conn.Close() })
		conns[i] = conn.(*net.UnixConn)
	}
	return conns[0], conns[1]
}

// startDaemonRelay sends the target line, followed by payload in the same write, to handleDaemonConnection
// and returns the main process's end of the UDS, the target's accepted connection, and a done channel.
func startDaemonRelay(t *testing.T, payload string) (*net.UnixConn, *net.TCPConn, <-chan struct{}) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	targetCh := acceptOne(t, ln)

	mainSide, daemonSide := unixPair(t)
	var wg sync.WaitGroup
	wg.Add(1)
	done := make(chan struct{})
	go func() {
		handleDaemonConnection(daemonSide, &wg)
		close(done)
	}()

	_, err = mainSide.Write([]byte(ln.Addr().String() + "\n" + payload))
	require.NoError(t, err)
	target := <-targetCh
	require.NotNil(t, target)
	t.Cleanup(func() { _ = target.Close() })
	return mainSide, target.(*net.TCPConn), done
}

func TestHandleDaemonConnectionDeliversResponseAfterMainHalfCloses(t *testing.T) {
	mainSide, target, done := startDaemonRelay(t, "")

	sendAndHalfClose(t, mainSide, target, "request")
	sendAndHalfClose(t, target, mainSide, "response")

	waitRelayDone(t, done)
}

func TestHandleDaemonConnectionCarriesMainDataAfterTargetHalfCloses(t *testing.T) {
	mainSide, target, done := startDaemonRelay(t, "")

	sendAndHalfClose(t, target, mainSide, "banner")
	sendAndHalfClose(t, mainSide, target, "late")

	waitRelayDone(t, done)
}

func TestHandleDaemonConnectionForwardsPayloadSentWithTargetLine(t *testing.T) {
	mainSide, target, done := startDaemonRelay(t, "request")

	require.NoError(t, mainSide.CloseWrite())

	assert.Equal(t, "request", readAllWithin(t, target))
	require.NoError(t, target.CloseWrite())
	waitRelayDone(t, done)
}

func TestHandleDaemonConnectionEndsBothDirectionsOnCopyError(t *testing.T) {
	mainSide, target, done := startDaemonRelay(t, "")

	require.NoError(t, target.SetLinger(0))
	require.NoError(t, target.Close())

	waitRelayDone(t, done)
	assert.Equal(t, "", readAllWithin(t, mainSide))
}
