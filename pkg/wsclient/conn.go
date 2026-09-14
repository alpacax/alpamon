// This file holds what it takes to own one connection: installing it,
// reading it, re-arming its deadline, deciding when it is ending, and taking
// it back out of service. The Ownership section of the package doc is the
// summary; these are the rules behind it.
//
// The invariant they exist to keep is gorilla/websocket's, that one
// goroutine reads and one writes. Run is the only reader, and everything
// here that a second goroutine may call reaches the socket through the
// net.Conn underneath, which does promise concurrent use.

package wsclient

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/gorilla/websocket"
)

const (
	// closeTimeout bounds sending the close frame and each control write.
	closeTimeout = 5 * time.Second

	// drainTimeout bounds waiting for the peer's reply to our close frame.
	// It is short because the wait is politeness, not correctness: a peer
	// that is draining or already gone is exactly the one that will not
	// answer, and every reconnect would otherwise stall for closeTimeout.
	drainTimeout = 1 * time.Second
)

// aLongTimeAgo is a read deadline already in the past. Setting it frees a
// parked read at once, whatever the clock says.
var aLongTimeAgo = time.Unix(1, 0)

// install makes conn the live connection, unless Run started stopping while
// conn was being dialed.
func (c *Client) install(ctx context.Context, conn *websocket.Conn) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.stopping(ctx) {
		return false
	}
	c.conn = conn
	c.reconnectPending, c.reconnectCause = false, nil
	return true
}

// disconnect says how a connection ended, which is what decides whether Run
// redials at once or waits out a backoff first.
type disconnect struct {
	proven bool  // it stayed up for at least MinBackoff
	cause  error // what ended it; nil only when the caller asked for the close
}

// serve reads conn into h until the connection ends, and releases it. It
// returns h's error when h stopped it, and nil otherwise.
func (c *Client) serve(ctx context.Context, conn *websocket.Conn, h Handler) (disconnect, error) {
	opened := time.Now()
	// end takes conn out of service and says how it ended. A connection that
	// lasted as long as the shortest backoff has shown the endpoint is worth
	// redialing at once; counting frames instead would let a peer that sends
	// one byte and hangs up reset the schedule every time. The proof is taken
	// before release, because the close drain and OnDisconnect run inside it,
	// and time spent there is not time the connection was up.
	end := func(cause error) disconnect {
		ended := disconnect{proven: time.Since(opened) >= c.s.minBackoff, cause: cause}
		c.release(conn, cause)
		return ended
	}

	// gorilla/websocket answers ping frames inside ReadMessage without
	// touching the read deadline, so a peer whose keepalive is a ping rather
	// than a data frame would hit ReadTimeout while talking to us.
	conn.SetPingHandler(func(appData string) error {
		// A conn that stops taking the deadline cannot keep the keepalive
		// contract; failing the read gives it up the way armRead would.
		if err := c.rearm(ctx, conn); err != nil {
			return err
		}
		// A pong the socket refused has failed the write side for good, as a
		// failed data frame does, and nothing else would notice: each ping
		// keeps the read deadline moving, so the connection would stay up
		// without being able to send. Fail the read, as gorilla's own ping
		// handler does. A pong that only timed out waiting for the write lock
		// behind a data frame is temporary and skipped; that frame's own
		// deadline decides the connection.
		err := conn.WriteControl(websocket.PongMessage, []byte(appData), time.Now().Add(closeTimeout))
		if err == nil || errors.Is(err, websocket.ErrCloseSent) || temporary(err) {
			return nil
		}
		return fmt.Errorf("wsclient: answering a ping: %w", err)
	})

	// An unsolicited pong is a heartbeat too, and RFC 6455 section 5.5.3
	// says so. gorilla/websocket hands it to this handler from inside
	// ReadMessage and reads on, exactly as it does a ping, so without one a
	// peer that beats this way would be talking steadily and still be cut at
	// ReadTimeout. Nothing to answer, only the deadline to move.
	conn.SetPongHandler(func(string) error { return c.rearm(ctx, conn) })

	for {
		if ending, cause := c.armRead(ctx, conn); ending {
			return end(cause), nil
		}
		messageType, payload, err := conn.ReadMessage()
		if err != nil {
			ending, cause := c.closeRequest(ctx)
			// Freeing a read produces a timeout, or net.ErrClosed when the
			// socket refused the deadline and freeRead closed it instead. Any
			// other error is the connection's own ending, a peer's close
			// frame among them, even if a request happened to be pending:
			// report that rather than the request.
			//
			// An organic ReadTimeout wears the same shape as a freed read, so
			// a write that fails in the window between the read returning and
			// this line takes the credit for a disconnect the timeout caused.
			// Only the reported cause is wrong: both are failures, so the
			// pacing is the same either way. Telling them apart would need
			// the free to carry a token the read could compare, and that is
			// not worth a generation counter on every read.
			if ending && wokenOnPurpose(err) {
				err = cause
			}
			return end(err), nil
		}
		if err := h(ctx, messageType, payload); err != nil {
			// A handler that honors its context reports the cancellation that
			// is already stopping Run. That is not a failure of its own, and
			// Run must still return nil for a Shutdown.
			if ctxErr := ctx.Err(); ctxErr != nil && errors.Is(err, ctxErr) {
				return end(nil), nil
			}
			return end(err), err
		}
	}
}

// armRead re-arms conn's read deadline, unless the connection is already
// ending, in which case it reports that and the cause instead. Checking and
// arming under one lock is what keeps a request from landing between the two
// and being overwritten by a fresh ReadTimeout.
func (c *Client) armRead(ctx context.Context, conn *websocket.Conn) (ending bool, cause error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if ending, cause := c.closeRequestLocked(ctx); ending {
		return true, cause
	}
	if err := conn.SetReadDeadline(time.Now().Add(c.s.readTimeout)); err != nil {
		// A caller-supplied net.Conn may refuse a deadline. Entering the
		// read anyway would park it with no timeout, and the interrupts
		// that free a parked read set the same deadline, so nothing could
		// end it. Give the connection up instead.
		return true, fmt.Errorf("wsclient: arming the read deadline: %w", err)
	}
	return false, nil
}

// rearm pushes the read deadline out again from the read goroutine, for a
// keepalive that ReadMessage handled without returning. It takes mu for the
// same reason armRead does: re-arming over a pending request would park the
// read for another ReadTimeout and lose the wakeup.
func (c *Client) rearm(ctx context.Context, conn *websocket.Conn) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if ending, _ := c.closeRequestLocked(ctx); ending || c.conn != conn {
		return nil
	}
	if err := conn.SetReadDeadline(time.Now().Add(c.s.readTimeout)); err != nil {
		return fmt.Errorf("wsclient: re-arming the read deadline: %w", err)
	}
	return nil
}

// freeRead unblocks a read parked on conn from a goroutine other than the
// reader. It works on the underlying net.Conn: gorilla/websocket counts its
// own SetReadDeadline among the read methods that only one goroutine may
// call, while net.Conn promises that any of its methods may be called
// concurrently. Pushing the deadline into the past is the ordinary way, but a
// caller-supplied net.Conn may refuse a deadline, and then closing the socket
// is the only thing left that ends the read; gorilla's Close is safe to call
// concurrently too.
func freeRead(conn *websocket.Conn) {
	if err := conn.UnderlyingConn().SetReadDeadline(aLongTimeAgo); err != nil {
		_ = conn.Close()
	}
}

// temporary reports what gorilla/websocket marks as passing: its own timeout
// waiting for the write lock is temporary, while a write that failed on the
// socket is stored as fatal and is not. A locally declared interface, not
// net.Error, because that interface's Temporary method is deprecated.
func temporary(err error) bool {
	var t interface{ Temporary() bool }
	return errors.As(err, &t) && t.Temporary()
}

// wokenOnPurpose reports whether a failed read is one this package caused
// to free it, as opposed to one the connection failed on by itself.
func wokenOnPurpose(err error) bool {
	var timeout net.Error
	return (errors.As(err, &timeout) && timeout.Timeout()) || errors.Is(err, net.ErrClosed)
}

// closeRequest reports whether the live connection is ending, and the cause
// OnDisconnect should report for it.
func (c *Client) closeRequest(ctx context.Context) (ending bool, cause error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closeRequestLocked(ctx)
}

// closeRequestLocked reports whether the connection is ending. A nil cause
// means the caller asked for the close; a non-nil one means something failed,
// which is what tells Run to pace the redial.
func (c *Client) closeRequestLocked(ctx context.Context) (ending bool, cause error) {
	if c.reconnectPending {
		return true, c.reconnectCause
	}
	return c.stopping(ctx), nil
}

// stopping reports whether Run should wind down. It reads the shutdown
// channel itself instead of waiting for the watcher to cancel ctx, so no
// dial can start in the gap between the two.
func (c *Client) stopping(ctx context.Context) bool {
	select {
	case <-c.shutdown:
		return true
	default:
		return ctx.Err() != nil
	}
}

// abandon asks Run to replace conn after a write on it failed, unless conn has
// already been replaced or a reconnect is already on its way.
func (c *Client) abandon(conn *websocket.Conn, cause error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn != conn || c.reconnectPending {
		return
	}
	c.reconnectPending = true
	c.reconnectCause = cause
	freeRead(conn)
}

// interrupt frees a read parked on the live connection. It holds mu, so it
// serializes with armRead: either armRead sees the request behind this call,
// or this call lands after armRead and cuts its deadline short.
func (c *Client) interrupt() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn != nil {
		freeRead(c.conn)
	}
}

// release takes conn out of service. It clears the field first, so writers
// get ErrNotConnected rather than a closing connection, then closes conn and
// reports the disconnect. cause is nil for a requested close.
func (c *Client) release(conn *websocket.Conn, cause error) {
	c.mu.Lock()
	if c.conn == conn {
		c.conn = nil
		c.reconnectPending, c.reconnectCause = false, nil
	}
	c.mu.Unlock()
	closeConn(conn)
	c.s.onDisconnect(cause)
}

// closeConn closes the socket whatever else fails, so a broken connection
// cannot leak its fd, and sends a close frame and waits briefly for the
// peer's reply first when it can. Only the goroutine that was reading conn
// calls it, so the drain is never a second concurrent reader.
//
// After a read that already failed, gorilla/websocket returns the stored
// error to every later read and the drain ends at once. When the close was
// noticed between reads the connection is still healthy, so the drain waits
// on the peer, which is why it is bounded by the short drainTimeout rather
// than by closeTimeout.
func closeConn(conn *websocket.Conn) {
	err := conn.WriteControl(websocket.CloseMessage,
		websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""),
		time.Now().Add(closeTimeout))
	// Only drain when the drain can be bounded: a conn that refuses the
	// deadline would leave NextReader waiting on a silent peer forever, and
	// Close, which is what actually matters, would never be reached.
	if err == nil && conn.SetReadDeadline(time.Now().Add(drainTimeout)) == nil {
		for {
			if _, _, err := conn.NextReader(); err != nil {
				break
			}
		}
	}
	_ = conn.Close()
}
