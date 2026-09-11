package wsclient

import (
	"context"
	"fmt"
	"net"
	"net/http"
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
// response is returned alongside it.
func Dial(ctx context.Context, cfg Config) (*websocket.Conn, *http.Response, error) {
	s, err := cfg.dialSettings()
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
	if err != nil {
		if resp != nil {
			// gorilla/websocket reports every rejected handshake as the same
			// ErrBadHandshake; the status is what tells a 401 from a 503.
			err = fmt.Errorf("%w (HTTP %d)", err, resp.StatusCode)
		}
		return nil, resp, err
	}

	// gorilla/websocket switches decompression on for any server that answers
	// with permessage-deflate, including one that was never offered it, and a
	// read limit counts the compressed bytes. Together that turns a small
	// frame into an unbounded allocation, so refuse the connection instead.
	if extensions := resp.Header.Get("Sec-WebSocket-Extensions"); extensions != "" && !s.dialer.EnableCompression {
		_ = conn.Close()
		return nil, resp, fmt.Errorf("wsclient: server negotiated %q, an extension this client did not offer", extensions)
	}

	conn.SetReadLimit(s.readLimit)
	return conn, resp, nil
}

// abortable copies d with its dial hooks wrapped so that every socket they
// open is unblocked once ctx ends, and returns a function to call when the
// dial is over.
//
// gorilla/websocket stops watching ctx as soon as the socket is up: the HTTP
// upgrade exchange, and a proxy CONNECT before it, are bounded only by
// HandshakeTimeout, which a caller-supplied dialer may leave at zero. Without
// this a Shutdown waits on a peer that has stopped answering, which for an
// agent in a pod means waiting out the termination grace period.
func abortable(ctx context.Context, d *websocket.Dialer) (*websocket.Dialer, func()) {
	dialer := *d

	var (
		mu       sync.Mutex
		opened   []net.Conn
		aborted  bool
		finished bool
	)
	track := func(c net.Conn) net.Conn {
		mu.Lock()
		defer mu.Unlock()
		if aborted {
			_ = c.SetDeadline(aLongTimeAgo)
		}
		opened = append(opened, c)
		return c
	}
	wrap := func(dial func(context.Context, string, string) (net.Conn, error)) func(context.Context, string, string) (net.Conn, error) {
		return func(ctx context.Context, network, addr string) (net.Conn, error) {
			c, err := dial(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			return track(c), nil
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

	stop := context.AfterFunc(ctx, func() {
		mu.Lock()
		defer mu.Unlock()
		if finished {
			return
		}
		aborted = true
		for _, c := range opened {
			_ = c.SetDeadline(aLongTimeAgo)
		}
	})

	return &dialer, func() {
		stop()
		mu.Lock()
		defer mu.Unlock()
		finished = true
		if !aborted {
			return
		}
		// The abort can land on a handshake that had already finished. Clear
		// it so a connection handed back to a caller is still usable; one
		// that is on its way out is closed by the caller either way.
		for _, c := range opened {
			_ = c.SetDeadline(time.Time{})
		}
	}
}
