package wsclient

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// Dial opens one connection and hands it over: the caller owns it outright,
// including reading, writing, deadlines and closing, and nothing reconnects
// it. It suits a connection with its own lifecycle, such as a tunnel data
// plane wrapped in tunnel.WebSocketConn for smux.
//
// Dial uses URL, ID, Key, Origin, UserAgent, Header, Dialer and ReadLimit
// from cfg, and ignores the timeout, backoff and hook fields. When the server
// rejects the handshake, the error wraps websocket.ErrBadHandshake and the
// response is returned alongside it, with the Authorization header stripped
// from the request hanging off it so that logging the response cannot spill
// the credential.
func Dial(ctx context.Context, cfg Config) (*websocket.Conn, *http.Response, error) {
	s, err := cfg.resolveDial()
	if err != nil {
		return nil, nil, err
	}
	return s.dial(ctx)
}

// dial opens one connection with the handshake headers and read limit.
func (s dialSettings) dial(ctx context.Context) (conn *websocket.Conn, resp *http.Response, err error) {
	dialer, finish := abortable(ctx, s.dialer)
	defer finish()

	// gorilla/websocket v1.5.3 reads the reason phrase out of a proxy's
	// CONNECT status line without checking there is one (proxy.go), so a
	// proxy answering "HTTP/1.1 407" panics whichever goroutine dialed. For
	// an agent that goroutine is the one keeping the process alive, and a
	// proxy is reachable by default through the environment, so turn it into
	// the error it should have been.
	defer func() {
		if r := recover(); r != nil {
			conn, resp, err = nil, nil, fmt.Errorf("wsclient: dial panicked, most likely on a malformed proxy response: %v", r)
		}
	}()

	conn, resp, err = dialer.DialContext(ctx, s.url, s.header)
	// http.ReadResponse hangs the request off the response, and that request
	// carries the Authorization header. Callers are invited to inspect the
	// response, and one logged struct would put the agent's long-lived key
	// wherever those logs go.
	if resp != nil && resp.Request != nil {
		resp.Request.Header.Del("Authorization")
	}
	if err != nil {
		if resp != nil {
			// gorilla/websocket reports every rejected handshake as the same
			// ErrBadHandshake; the status is what tells a 401 from a 503.
			err = fmt.Errorf("%w (HTTP %d)", err, resp.StatusCode)
		}
		return nil, resp, err
	}

	// A client must fail the connection when the server answers with an
	// extension it never offered (RFC 6455, section 9.1), and here it matters
	// beyond form: gorilla/websocket switches decompression on for any
	// permessage-deflate answer, offered or not, and a read limit counts the
	// compressed bytes, so a small frame could inflate without bound.
	// Values, not Get, because gorilla reads every Sec-WebSocket-Extensions
	// header, so a server that hid the real one behind an empty first header
	// would pass a check on the first value alone.
	if name, ok := unofferedExtension(resp.Header.Values("Sec-WebSocket-Extensions"), s.dialer.EnableCompression); ok {
		_ = conn.Close()
		return nil, resp, fmt.Errorf("wsclient: server negotiated %q, an extension this client did not offer", name)
	}

	conn.SetReadLimit(s.readLimit)
	return conn, resp, nil
}

// unofferedExtension returns the first extension named in the server's
// answer that this client did not offer. The only extension gorilla/websocket
// ever offers is permessage-deflate, and only with EnableCompression. Anything
// this parser cannot place is reported rather than skipped, so a header it
// reads differently from gorilla fails closed.
func unofferedExtension(values []string, compression bool) (string, bool) {
	for _, value := range values {
		for _, extension := range strings.Split(value, ",") {
			name, _, _ := strings.Cut(extension, ";")
			name = strings.TrimSpace(name)
			switch {
			case name == "":
			case compression && strings.EqualFold(name, "permessage-deflate"):
			default:
				return name, true
			}
		}
	}
	return "", false
}

// abortable copies d with its dial hooks wrapped so that every socket they
// open is unblocked once ctx ends, and returns a function to call when the
// dial is over.
//
// gorilla/websocket stops watching ctx as soon as the socket is up: the HTTP
// upgrade exchange, and a proxy CONNECT before it, are bounded only by
// HandshakeTimeout. Without this a Shutdown would wait that timeout out on a
// peer that has stopped answering, 30 seconds by default, which for an agent
// in a pod is the whole termination grace period.
func abortable(ctx context.Context, d *websocket.Dialer) (*websocket.Dialer, func()) {
	dialer := *d
	state := &abortState{}
	wrap := func(dial func(context.Context, string, string) (net.Conn, error)) func(context.Context, string, string) (net.Conn, error) {
		return func(ctx context.Context, network, addr string) (net.Conn, error) {
			c, err := dial(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			return state.track(c), nil
		}
	}

	base := dialer.NetDialContext
	switch {
	case base != nil:
	case dialer.NetDial != nil:
		netDial := dialer.NetDial
		base = func(_ context.Context, network, addr string) (net.Conn, error) { return netDial(network, addr) }
	default:
		var nd net.Dialer
		base = nd.DialContext
	}
	dialer.NetDial = nil // NetDialContext wins anyway; leaving it would only mislead
	dialer.NetDialContext = wrap(base)
	if dialer.NetDialTLSContext != nil {
		dialer.NetDialTLSContext = wrap(dialer.NetDialTLSContext)
	}

	stop := context.AfterFunc(ctx, state.abort)
	return &dialer, func() {
		stop()
		state.finish()
	}
}

// abortState is what one dial's sockets share. Every field is read and
// written under mu, and so is every deadline that reaches a socket through
// abortableConn, which is the point: an abort and a deadline on its way down
// both end in a SetDeadline on the same socket, and whichever lands second
// decides how long the dial waits. Holding mu across the call keeps the
// abort's deadline from being the first of the two.
//
// opened holds the sockets as the dial hook returned them, not the wrappers,
// so nothing below re-enters abortableConn and deadlocks on mu.
type abortState struct {
	mu       sync.Mutex
	opened   []net.Conn
	aborted  bool
	finished bool
}

// track takes ownership of a freshly opened socket and returns it wrapped.
func (s *abortState) track(c net.Conn) net.Conn {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.aborted {
		_ = forceAbort(c) // it closes what refuses the deadline; nothing left to do
	}
	s.opened = append(s.opened, c)
	return abortableConn{Conn: c, state: s}
}

// abort unblocks every socket the dial has opened, and every socket it opens
// from here on.
func (s *abortState) abort() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.finished {
		return
	}
	s.aborted = true
	for _, c := range s.opened {
		_ = forceAbort(c)
	}
}

// setDeadline installs t on c, unless the dial has been aborted, in which
// case the abort's deadline is the one that stands.
func (s *abortState) setDeadline(c net.Conn, t time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.aborted {
		return forceAbort(c)
	}
	return c.SetDeadline(t)
}

// finish ends the dial and lifts an abort that landed on it.
func (s *abortState) finish() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.finished = true
	if !s.aborted {
		return
	}
	s.aborted = false
	// The abort can land on a handshake that had already finished. Clear it
	// so a connection handed back to a caller is still usable; one that is on
	// its way out is closed by the caller either way.
	for _, c := range s.opened {
		_ = c.SetDeadline(time.Time{})
	}
}

// abortableConn keeps an aborted dial aborted. gorilla/websocket sets its own
// handshake deadline on whatever the dial hook returned, outside this
// package's wrapper, so without this an abort landing in that window would be
// quietly overwritten and the dial would run to its handshake timeout.
type abortableConn struct {
	net.Conn
	state *abortState
}

func (c abortableConn) SetDeadline(t time.Time) error {
	return c.state.setDeadline(c.Conn, t)
}

// forceAbort unblocks a dial on c. A deadline in the past is the ordinary
// way, but a caller-supplied net.Conn may refuse deadlines, and then closing
// it is what is left.
func forceAbort(c net.Conn) error {
	if err := c.SetDeadline(aLongTimeAgo); err != nil {
		_ = c.Close()
		return err
	}
	return nil
}
