package runner

import (
	"errors"
	"io"
	"net"
	"time"

	"github.com/alpacax/alpamon/v2/pkg/tunnel"
	"github.com/rs/zerolog/log"
)

// halfCloseTimeout caps the direction left open after the other ends cleanly. A reader gets the same
// EOF whether its peer half-closed or left, so a target writing to a departed peer would run forever.
const halfCloseTimeout = 5 * time.Minute

// relayBidirectional copies fromA to b and fromB to a, then closes both before returning. fromA and
// fromB read a and b, after any bytes already buffered off them.
func relayBidirectional(a net.Conn, fromA io.Reader, b net.Conn, fromB io.Reader, bound time.Duration) {
	errChan := make(chan error, 2)
	pipe := func(dst net.Conn, src io.Reader) {
		_, err := tunnel.CopyBuffered(dst, src)
		if err == nil {
			closeWriteSide(dst)
		}
		errChan <- err
	}
	go pipe(b, fromA)
	go pipe(a, fromB)

	first := <-errChan
	if first == nil { // the other direction gets bound to finish
		deadline := time.Now().Add(bound)
		_ = a.SetDeadline(deadline)
		_ = b.SetDeadline(deadline)
	} else { // closing both ends unblocks the goroutine still copying
		_ = a.Close()
		_ = b.Close()
	}
	var netErr net.Error
	if err := <-errChan; first == nil && errors.As(err, &netErr) && netErr.Timeout() {
		log.Info().Dur("bound", bound).Msg("Relay closed a half-closed connection at its time bound.")
	}
	_ = a.Close()
	_ = b.Close()
}

// closeWriteSide signals EOF to the peer through conn's CloseWrite; a conn without one is left alone.
func closeWriteSide(conn net.Conn) {
	if cw, ok := conn.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	}
}
