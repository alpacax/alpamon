package runner

import (
	"io"
	"net"
	"testing"
	"testing/synctest"
	"time"

	"github.com/alpacax/alpamon/v2/pkg/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xtaci/smux"
)

type halfCloser interface {
	net.Conn
	CloseWrite() error
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

// sendAndHalfClose writes msg from one end, half-closes it, and asserts the other end reads exactly msg.
func sendAndHalfClose(t *testing.T, from halfCloser, to net.Conn, msg string) {
	t.Helper()
	_, err := from.Write([]byte(msg))
	require.NoError(t, err)
	require.NoError(t, from.CloseWrite())
	assert.Equal(t, msg, readAllWithin(t, to))
}

func waitRelayDone(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("relay did not return")
	}
}

func relayDone(done <-chan struct{}) bool {
	select {
	case <-done:
		return true
	default:
		return false
	}
}

// smuxPair returns a stream and its peer over an in-memory session using the tunnel's smux config.
func smuxPair(t *testing.T) (*smux.Stream, *smux.Stream) {
	t.Helper()
	agentConn, serverConn := net.Pipe()
	agentSession, err := smux.Client(agentConn, config.GetSmuxConfig())
	require.NoError(t, err)
	serverSession, err := smux.Server(serverConn, config.GetSmuxConfig())
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = agentSession.Close()
		_ = serverSession.Close()
	})

	peer, err := serverSession.OpenStream()
	require.NoError(t, err)
	stream, err := agentSession.AcceptStream()
	require.NoError(t, err)
	return stream, peer
}

// startClientRelay relays a smux stream to a TCP target, as handleStream does on Windows, and returns
// the stream's peer, the target service's end, and a done channel.
func startClientRelay(t *testing.T, bound time.Duration) (*smux.Stream, *net.TCPConn, <-chan struct{}) {
	t.Helper()
	stream, peer := smuxPair(t)
	agentSide, service := tcpPair(t)
	done := make(chan struct{})
	go func() {
		relayBidirectional(stream, stream, agentSide, agentSide, bound)
		close(done)
	}()
	return peer, service, done
}

// startPipeRelay relays two net.Pipe pairs, whose deadlines follow the synctest clock, and returns
// the peer's end, the target service's end, and a done channel.
func startPipeRelay(bound time.Duration) (net.Conn, net.Conn, <-chan struct{}) {
	agentStream, peer := net.Pipe()
	agentTarget, service := net.Pipe()
	done := make(chan struct{})
	go func() {
		relayBidirectional(agentStream, agentStream, agentTarget, agentTarget, bound)
		close(done)
	}()
	return peer, service, done
}

func TestCloseWriteSide(t *testing.T) {
	t.Run("tcp conn delivers EOF but keeps read side open", func(t *testing.T) {
		client, server := tcpPair(t)

		closeWriteSide(client)

		// Server sees EOF on read...
		buf := make([]byte, 1)
		_, err := server.Read(buf)
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

func TestRelayBidirectionalDeliversResponseAfterStreamHalfCloses(t *testing.T) {
	peer, service, done := startClientRelay(t, time.Minute)

	sendAndHalfClose(t, peer, service, "request")
	sendAndHalfClose(t, service, peer, "response")

	waitRelayDone(t, done)
}

func TestRelayBidirectionalCarriesStreamDataAfterTargetHalfCloses(t *testing.T) {
	peer, service, done := startClientRelay(t, time.Minute)

	sendAndHalfClose(t, service, peer, "banner")
	sendAndHalfClose(t, peer, service, "late")

	waitRelayDone(t, done)
}

// smux pools its channels package-wide, so a smux test cannot run inside a synctest bubble.
func TestRelayBidirectionalClosesBusyTargetAtBoundAfterPeerCloses(t *testing.T) {
	peer, service, done := startClientRelay(t, 200*time.Millisecond)

	require.NoError(t, peer.Close())
	assert.Equal(t, "", readAllWithin(t, service))

	writeErr := make(chan error, 1)
	go func() {
		chunk := make([]byte, 4096)
		for {
			if _, err := service.Write(chunk); err != nil {
				writeErr <- err
				return
			}
		}
	}()

	waitRelayDone(t, done)
	select {
	case <-writeErr:
	case <-time.After(5 * time.Second):
		t.Fatal("target kept writing after the relay returned")
	}
}

func TestRelayBidirectionalClosesQuietTargetAtBoundAfterPeerCloses(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		peer, service, done := startPipeRelay(time.Minute)

		require.NoError(t, peer.Close())
		time.Sleep(time.Minute - time.Millisecond)
		synctest.Wait()
		require.False(t, relayDone(done), "relay closed before its bound")

		time.Sleep(2 * time.Millisecond)
		synctest.Wait()
		require.True(t, relayDone(done), "relay outlived its bound")
		data, err := io.ReadAll(service)
		require.NoError(t, err)
		assert.Empty(t, data)
	})
}

// stalledConn stands in for a smux v1 stream on a stalled session: a Write already queued ignores
// later deadlines and Close until the session drains.
type stalledConn struct {
	net.Conn
	drained chan struct{}
}

func (c *stalledConn) Write([]byte) (int, error) {
	<-c.drained
	return 0, net.ErrClosed
}

func TestRelayBidirectionalReturnsAtBoundWhileAWriteIsStalled(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		agentStream, peer := net.Pipe()
		agentTarget, service := net.Pipe()
		stream := &stalledConn{Conn: agentStream, drained: make(chan struct{})}
		done := make(chan struct{})
		go func() {
			relayBidirectional(stream, stream, agentTarget, agentTarget, time.Minute)
			close(done)
		}()
		go func() { _, _ = service.Write([]byte("response")) }()
		synctest.Wait()

		require.NoError(t, peer.Close())
		time.Sleep(time.Minute + time.Millisecond)
		synctest.Wait()

		require.True(t, relayDone(done), "relay waited past its bound on a stalled write")
		close(stream.drained)
	})
}

func TestRelayBidirectionalKeepsOpenRelayPastBoundUntilADirectionEnds(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		peer, service, done := startPipeRelay(time.Minute)

		time.Sleep(2 * time.Minute)
		synctest.Wait()
		require.False(t, relayDone(done), "relay closed while both directions were open")

		go func() { _, _ = peer.Write([]byte("ping")) }()
		buf := make([]byte, 4)
		_, err := io.ReadFull(service, buf)
		require.NoError(t, err)
		assert.Equal(t, "ping", string(buf))

		require.NoError(t, peer.Close())
		time.Sleep(time.Minute - time.Millisecond)
		synctest.Wait()
		require.False(t, relayDone(done), "relay cut the remaining direction before its bound")
		_ = service.Close()
		<-done
	})
}

func TestRelayBidirectionalEndsBothDirectionsOnCopyError(t *testing.T) {
	peer, service, done := startClientRelay(t, time.Hour)

	require.NoError(t, service.SetLinger(0))
	require.NoError(t, service.Close())

	waitRelayDone(t, done)
	assert.Equal(t, "", readAllWithin(t, peer))
}
