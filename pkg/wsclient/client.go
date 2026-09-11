package wsclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
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

var (
	// ErrNotConnected is returned by a write made while no connection is up,
	// for example between a drop and the reconnect that follows it.
	ErrNotConnected = errors.New("wsclient: not connected")

	// ErrAlreadyRunning is returned by Run on a Client whose Run has already
	// been called. A Client is single-use.
	ErrAlreadyRunning = errors.New("wsclient: Run has already been called")
)

// Handler receives each inbound frame. It runs on the Run goroutine, so the
// next frame is not read until it returns: hand long work to another
// goroutine. ctx is done once Run starts stopping. A non-nil error stops Run,
// which returns it; call Shutdown for an ordinary stop.
type Handler func(ctx context.Context, messageType int, payload []byte) error

// Client keeps one WebSocket connection up: it dials, reconnects with
// jittered backoff whenever the connection drops, and hands every inbound
// frame to a Handler.
//
// The Client owns its connection. Run is the only goroutine that reads it,
// writes are serialized, and Reconnect and Shutdown only signal the read
// loop, so gorilla/websocket's one-reader, one-writer rule holds without the
// caller's help. All methods are safe for concurrent use.
type Client struct {
	s settings

	// mu guards conn and the pending-reconnect pair. Nothing slower than
	// SetReadDeadline happens while it is held.
	mu   sync.Mutex
	conn *websocket.Conn
	// reconnectPending asks Run to replace conn; reconnectCause is what
	// OnDisconnect then reports: nil for Reconnect, the write error for a
	// connection a failed write abandoned. Both reset whenever conn changes.
	reconnectPending bool
	reconnectCause   error

	// writeMu serializes data frames. Lock order is writeMu, then mu.
	writeMu sync.Mutex

	started      atomic.Bool
	shutdownOnce sync.Once
	shutdown     chan struct{}
	done         chan struct{}
}

// New validates cfg and returns a Client ready to Run. It does not dial.
func New(cfg Config) (*Client, error) {
	s, err := cfg.resolve()
	if err != nil {
		return nil, err
	}
	return &Client{
		s:        s,
		shutdown: make(chan struct{}),
		done:     make(chan struct{}),
	}, nil
}

// Run dials, then feeds every inbound frame to h until Shutdown is called,
// ctx is done, or h returns an error, reconnecting whenever the connection
// drops. It keeps trying for as long as it runs; OnRetry reports every wait,
// so a caller that wants to give up can call Shutdown.
//
// The backoff paces attempts, not just failed dials. Anything that ends a
// connection short of MinBackoff is followed by the same jittered wait a
// failed dial gets, whether the dial was refused, the peer hung up, or a
// write failed. Only a connection that lasted at least MinBackoff, or a close
// the caller asked for through Reconnect or Shutdown, redials at once and
// restarts the schedule. Without that, a peer that accepts the handshake and
// drops it can drive a redial loop across a whole fleet.
//
// Run returns nil after Shutdown, ctx.Err() once ctx is done, and h's error
// when h stopped it. The connection is closed before Run returns. A Client
// runs once: a second call returns ErrAlreadyRunning.
func (c *Client) Run(ctx context.Context, h Handler) error {
	if !c.started.CompareAndSwap(false, true) {
		return ErrAlreadyRunning
	}
	defer close(c.done)
	if h == nil {
		return errors.New("wsclient: Run needs a non-nil Handler")
	}

	// runCtx also ends on Shutdown, so one context aborts a dial in flight,
	// a backoff wait and the handler alike. A parked read ignores contexts,
	// which is why the watcher also interrupts it.
	runCtx, cancel := context.WithCancel(ctx)
	var wg sync.WaitGroup
	wg.Go(func() {
		select {
		case <-c.shutdown:
			cancel()
		case <-runCtx.Done():
		}
		c.interrupt()
	})
	defer func() {
		cancel()
		wg.Wait()
	}()

	b := &backoff{initial: c.s.minBackoff, max: c.s.maxBackoff, rand: c.s.rand}
	var (
		attempt int   // attempts since the last connection that worked
		wait    bool  // whether the next attempt waits out a backoff first
		cause   error // what made it wait
	)
	for {
		// Checked before the wait as well as before the dial, so a Shutdown
		// neither dials again nor reports a retry that will never happen.
		if c.stopping(runCtx) {
			return ctx.Err()
		}
		if wait {
			attempt++
			delay := b.next()
			c.s.onRetry(attempt, delay, cause)
			if !c.sleep(runCtx, delay) {
				return ctx.Err()
			}
		}

		conn, _, err := c.s.dial(runCtx)
		if err != nil {
			wait, cause = true, err
			continue
		}
		if !c.install(runCtx, conn) {
			closeConn(conn)
			return ctx.Err()
		}
		c.s.onConnect()

		ended, handlerErr := c.serve(runCtx, conn, h)
		if handlerErr != nil {
			return handlerErr
		}
		// A close with no failure behind it is one the caller asked for, and
		// it redials at once. Everything else is a failure, and only a
		// connection that lasted earns the same treatment.
		if ended.cause == nil || ended.proven {
			b.reset()
			attempt, wait, cause = 0, false, nil
			continue
		}
		wait, cause = true, ended.cause
	}
}

// sleep waits out d, and reports false if Run should stop instead.
func (c *Client) sleep(ctx context.Context, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-ctx.Done():
		return false
	case <-c.shutdown:
		return false
	}
}

// WriteMessage sends one data frame on the live connection. messageType must
// be websocket.TextMessage or websocket.BinaryMessage: control frames belong
// to the Client. It returns ErrNotConnected while no connection is up, and
// never queues a frame for a later connection. A failed write leaves the
// connection unable to send, so it also makes Run replace the connection.
func (c *Client) WriteMessage(messageType int, data []byte) error {
	if messageType != websocket.TextMessage && messageType != websocket.BinaryMessage {
		// gorilla/websocket would send a close frame given here, and every
		// later write would then fail behind the read loop's back.
		return fmt.Errorf("wsclient: WriteMessage sends data frames only, got message type %d", messageType)
	}

	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	c.mu.Lock()
	conn := c.conn
	c.mu.Unlock()
	if conn == nil {
		return ErrNotConnected
	}
	// gorilla/websocket keeps the write deadline in a plain field that the
	// next write reads, so setting it is only safe under writeMu.
	if err := conn.SetWriteDeadline(time.Now().Add(c.s.writeTimeout)); err != nil {
		return fmt.Errorf("wsclient: setting the write deadline: %w", err)
	}
	if err := conn.WriteMessage(messageType, data); err != nil {
		// gorilla/websocket fails every later write once one has failed, so
		// this connection can no longer send. Replace it now rather than
		// wait for the read side to notice.
		c.abandon(conn, err)
		return err
	}
	return nil
}

// WriteJSON sends v, encoded as JSON, as one text frame.
func (c *Client) WriteJSON(v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("wsclient: encoding the message: %w", err)
	}
	return c.WriteMessage(websocket.TextMessage, data)
}

// Reconnect drops the live connection so that Run dials a fresh one, as when
// the server asks the agent to reconnect. While no connection is up it does
// nothing, since Run is already dialing. It does not block.
func (c *Client) Reconnect() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn == nil || c.reconnectPending {
		return
	}
	c.reconnectPending = true
	c.reconnectCause = nil
	freeRead(c.conn)
}

// Shutdown makes Run close the connection and return. It does not wait; Done
// does. Calling it more than once, before Run, or after Run returned is safe.
func (c *Client) Shutdown() {
	c.shutdownOnce.Do(func() { close(c.shutdown) })
}

// Done is closed once Run has returned. It never closes if Run is never called.
func (c *Client) Done() <-chan struct{} {
	return c.done
}

// Connected reports whether a connection is up. It is a snapshot: the
// connection may drop the moment after it returns true.
func (c *Client) Connected() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.conn != nil
}

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
	// A connection that lasted as long as the shortest backoff has shown the
	// endpoint is worth redialing at once. Counting frames instead would let
	// a peer that sends one byte and hangs up reset the schedule every time.
	proven := func() bool { return time.Since(opened) >= c.s.minBackoff }

	// gorilla/websocket answers ping frames inside ReadMessage without
	// touching the read deadline, so a peer whose keepalive is a ping rather
	// than a data frame would hit ReadTimeout while talking to us.
	conn.SetPingHandler(func(appData string) error {
		c.rearm(ctx, conn)
		// A pong that cannot go out means the connection is already failing,
		// and the read that follows will say so; ending the read here would
		// only lose that reason.
		_ = conn.WriteControl(websocket.PongMessage, []byte(appData), time.Now().Add(closeTimeout))
		return nil
	})

	for {
		if cause, ending := c.armRead(ctx, conn); ending {
			c.release(conn, cause)
			return disconnect{proven: proven(), cause: cause}, nil
		}
		messageType, payload, err := conn.ReadMessage()
		if err != nil {
			cause, ending := c.closeRequest(ctx)
			// Freeing a read produces a timeout and nothing else, so any
			// other error is the connection's own ending, even if a request
			// happened to be pending: report that rather than the request.
			var timeout net.Error
			if ending && errors.As(err, &timeout) && timeout.Timeout() {
				err = cause
			}
			c.release(conn, err)
			return disconnect{proven: proven(), cause: err}, nil
		}
		if err := h(ctx, messageType, payload); err != nil {
			// A handler that honors its context reports the cancellation that
			// is already stopping Run. That is not a failure of its own, and
			// Run must still return nil for a Shutdown.
			if ctxErr := ctx.Err(); ctxErr != nil && errors.Is(err, ctxErr) {
				c.release(conn, nil)
				return disconnect{proven: proven()}, nil
			}
			c.release(conn, err)
			return disconnect{proven: proven(), cause: err}, err
		}
	}
}

// armRead re-arms conn's read deadline, unless the connection is already
// ending, in which case it reports that and the cause instead. Checking and
// arming under one lock is what keeps a request from landing between the two
// and being overwritten by a fresh ReadTimeout.
func (c *Client) armRead(ctx context.Context, conn *websocket.Conn) (cause error, ending bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if cause, ending := c.closeRequestLocked(ctx); ending {
		return cause, true
	}
	if err := conn.SetReadDeadline(time.Now().Add(c.s.readTimeout)); err != nil {
		// A caller-supplied net.Conn may refuse a deadline. Entering the
		// read anyway would park it with no timeout, and the interrupts
		// that free a parked read set the same deadline, so nothing could
		// end it. Give the connection up instead.
		return fmt.Errorf("wsclient: arming the read deadline: %w", err), true
	}
	return nil, false
}

// rearm pushes the read deadline out again from the read goroutine, for a
// keepalive that ReadMessage handled without returning. It takes mu for the
// same reason armRead does: re-arming over a pending request would park the
// read for another ReadTimeout and lose the wakeup.
func (c *Client) rearm(ctx context.Context, conn *websocket.Conn) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ending := c.closeRequestLocked(ctx); ending || c.conn != conn {
		return
	}
	_ = conn.SetReadDeadline(time.Now().Add(c.s.readTimeout))
}

// freeRead unblocks a read parked on conn. Pushing the deadline into the
// past is the ordinary way, but a caller-supplied net.Conn may refuse a
// deadline, and then closing the socket is the only thing left that ends the
// read. Both are safe to call while another goroutine is reading.
func freeRead(conn *websocket.Conn) {
	if err := conn.SetReadDeadline(aLongTimeAgo); err != nil {
		_ = conn.Close()
	}
}

// closeRequest reports whether the live connection is ending, and the cause
// OnDisconnect should report for it.
func (c *Client) closeRequest(ctx context.Context) (cause error, ending bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closeRequestLocked(ctx)
}

// closeRequestLocked reports whether the connection is ending. A nil cause
// means the caller asked for the close; a non-nil one means something failed,
// which is what tells Run to pace the redial.
func (c *Client) closeRequestLocked(ctx context.Context) (cause error, ending bool) {
	if c.reconnectPending {
		return c.reconnectCause, true
	}
	return nil, c.stopping(ctx)
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

// closeConn sends a close frame, waits briefly for the peer's reply when that
// frame went out, and closes the socket regardless, so a broken connection
// cannot leak its fd. Only the goroutine that was reading conn calls it, so
// the drain is never a second concurrent reader.
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
	if err == nil {
		_ = conn.SetReadDeadline(time.Now().Add(drainTimeout))
		for {
			if _, _, err := conn.NextReader(); err != nil {
				break
			}
		}
	}
	_ = conn.Close()
}
