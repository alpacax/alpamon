package runner

import (
	"io"
	"net"
	"time"

	"github.com/alpacax/alpamon/v2/pkg/tunnel"
)

// halfCloseTimeout caps the direction left open after the other ends cleanly. A reader gets the same
// EOF whether its peer half-closed or left, so a target writing to a departed peer would run forever.
const halfCloseTimeout = 5 * time.Minute

// relayBidirectional copies fromA to b and fromB to a, then closes both before returning. fromA and
// fromB read a and b, after any bytes already buffered off them. cut reports that the bound ended it.
func relayBidirectional(a net.Conn, fromA io.Reader, b net.Conn, fromB io.Reader, bound time.Duration) (cut bool) {
	errChan := make(chan error, 2)
	pipe := func(dst net.Conn, src io.Reader) {
		_, err := tunnel.CopyBuffered(dst, src)
		if err == nil {
			closeWriteSide(dst) // smux holds a FIN up to its 30s close timeout, delaying the bound by as much
		}
		errChan <- err
	}
	go pipe(b, fromA)
	go pipe(a, fromB)

	if <-errChan == nil { // the other direction gets bound to finish
		select {
		case <-errChan:
		case <-time.After(bound):
			cut = true
		}
	}
	// Closing ends the other copy, except a smux v1 Write already queued on a stalled session, which
	// ignores later deadlines and closes; the relay returns without waiting for it.
	_ = a.Close()
	_ = b.Close()
	return cut
}

// closeWriteSide signals EOF to the peer through conn's CloseWrite; a conn without one is left alone.
func closeWriteSide(conn net.Conn) {
	if cw, ok := conn.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	}
}
