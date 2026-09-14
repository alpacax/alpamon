package wsclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
)

var (
	// ErrNotConnected is returned by a write made while no connection is up,
	// for example between a drop and the reconnect that follows it.
	ErrNotConnected = errors.New("wsclient: not connected")

	// ErrAlreadyRunning is returned by Run on a Client whose Run has already
	// been called. A Client is single-use.
	ErrAlreadyRunning = errors.New("wsclient: Run has already been called")
)

// Handler receives each inbound message. It runs on the Run goroutine, so
// the next message is not read until it returns: hand long work to another
// goroutine. ctx is done once Run starts stopping. A non-nil error stops Run,
// which returns it; call Shutdown for an ordinary stop.
type Handler func(ctx context.Context, messageType int, payload []byte) error

// Client keeps one WebSocket connection up: it dials, reconnects with
// jittered backoff whenever the connection drops, and hands every inbound
// message to a Handler.
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
	// reconnectPending asks Run to replace conn; reconnectCause says why:
	// nil for Reconnect, the write error for a connection a failed write
	// abandoned. The cause is reported only when the read ended on the
	// wakeup this request sent; a peer's own close or error reaches the read
	// first and outranks it, which is what wokenOnPurpose decides. Both
	// reset whenever conn changes.
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

// Run dials, then feeds every inbound message to h until Shutdown is called,
// ctx is done, or h returns an error, reconnecting whenever the connection
// drops. It keeps trying for as long as it runs; OnRetry reports every wait,
// so a caller that wants to give up can call Shutdown.
//
// The backoff paces attempts, not just failed dials. Anything that ends a
// connection short of MinBackoff is followed by the same jittered wait a
// failed dial gets, whether the dial was refused, the peer hung up, or a
// write failed. Only a connection that lasted at least MinBackoff, or a close
// the caller asked for through Reconnect, redials at once and restarts the
// schedule; Shutdown and a done ctx end Run instead. Without that, a peer
// that accepts the handshake and drops it can drive a redial loop across a
// whole fleet.
//
// Run returns nil after Shutdown, ctx.Err() once ctx is done, and h's error
// when h stopped it. The connection is closed before Run returns. A Client
// runs once: a second call returns ErrAlreadyRunning.
//
// It returns that promptly as far as the caller's own code lets it. h, the
// three hooks and the dialer's dial hook all run on Run's goroutine, so one
// that blocks holds Run there; a dial hook is the one to watch, because it
// can be waiting on a socket that does not exist yet and so cannot be freed.
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
		cause   error // what ended the last attempt; non-nil means pace the next
	)
	for {
		// Checked before the wait as well as before the dial, so a Shutdown
		// neither dials again nor reports a retry that will never happen.
		if c.stopping(runCtx) {
			return ctx.Err()
		}
		if cause != nil {
			attempt++
			delay := b.next()
			c.s.onRetry(attempt, delay, cause)
			if !c.sleep(runCtx, delay) {
				return ctx.Err()
			}
		}

		conn, _, err := c.s.dial(runCtx)
		if err != nil {
			cause = err
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
			attempt, cause = 0, nil
			continue
		}
		cause = ended.cause
	}
}

// sleep waits out d, and reports false if Run should stop instead.
func (c *Client) sleep(ctx context.Context, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-timer.C:
		// A stop that arrives as the timer fires leaves both cases ready,
		// and a select picks among ready cases at random, so the timer wins
		// half of those. Ask again rather than send Run off to dial on an
		// answer that was already there: that dial is a connect to the
		// backhaul, and a call into a caller's own dial hook, made after the
		// caller asked the client to stop.
		return !c.stopping(ctx)
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
	deadline := time.Now().Add(c.s.writeTimeout)
	// gorilla/websocket applies the write deadline to the socket before each
	// frame but drops the error, so a net.Conn that refuses write deadlines
	// would get writes with no bound at all. Ask the socket directly, and give
	// up a connection that cannot enforce WriteTimeout. The probe is safe from
	// here: net.Conn methods may be called concurrently.
	if err := conn.UnderlyingConn().SetWriteDeadline(deadline); err != nil {
		err = fmt.Errorf("wsclient: arming the write deadline: %w", err)
		c.abandon(conn, err)
		return err
	}
	// gorilla keeps the deadline in a plain field that it re-applies per
	// frame; the field is only safe to set under writeMu. It never errors.
	_ = conn.SetWriteDeadline(deadline)
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
