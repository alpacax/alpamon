//go:build !windows

package runner

// Regression tests for issue #351: repeated Websh reconnects must not deadlock when only one side waits for recovery, and close() must release the connection even when the close handshake fails.

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alpacax/alpamon/v2/pkg/config"
	"github.com/alpacax/alpamon/v2/pkg/scheduler"
	"github.com/gorilla/websocket"
)

// wshServer is a local Websh test double: a WebSocket endpoint plus the pty-channels recovery API, with server-side handles to kill connections.
type wshServer struct {
	ts            *httptest.Server
	mu            sync.Mutex
	conns         []*websocket.Conn
	recoveryPosts atomic.Int32
}

func newWshServer(t *testing.T) *wshServer {
	t.Helper()
	s := &wshServer{}
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}

	mux := http.NewServeMux()
	mux.HandleFunc("/ws/pty", func(w http.ResponseWriter, r *http.Request) {
		c, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		s.mu.Lock()
		s.conns = append(s.conns, c)
		s.mu.Unlock()
	})
	mux.HandleFunc(reconnectPtyWebsocketURL, func(w http.ResponseWriter, r *http.Request) {
		s.recoveryPosts.Add(1)
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"websocket_url": "/ws/pty"}`))
	})

	s.ts = httptest.NewServer(mux)
	t.Cleanup(s.ts.Close)

	prevServerURL := config.GlobalSettings.ServerURL
	config.GlobalSettings.ServerURL = s.ts.URL
	t.Cleanup(func() { config.GlobalSettings.ServerURL = prevServerURL })

	return s
}

func (s *wshServer) wsURL() string {
	return strings.Replace(s.ts.URL, "http", "ws", 1) + "/ws/pty"
}

// killConn abruptly closes the n-th (0-based) server-side connection, simulating a network drop without a close handshake.
func (s *wshServer) killConn(t *testing.T, n int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		s.mu.Lock()
		if len(s.conns) > n {
			c := s.conns[n]
			s.mu.Unlock()
			_ = c.UnderlyingConn().Close()
			return
		}
		s.mu.Unlock()
		if time.Now().After(deadline) {
			t.Fatalf("server-side connection #%d never appeared", n)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// newTestPtyClient returns a PtyClient connected to the test server, without a PTY or shell process (WebSocket recovery does not need them).
func newTestPtyClient(t *testing.T, s *wshServer) *PtyClient {
	t.Helper()
	dialer := websocket.Dialer{}
	conn, _, err := dialer.Dial(s.wsURL(), nil)
	if err != nil {
		t.Fatal(err)
	}

	return &PtyClient{
		conn:         conn,
		apiSession:   &scheduler.Session{BaseURL: s.ts.URL, Client: s.ts.Client()},
		sessionID:    "test-session",
		wsToPty:      make(chan []byte, bufferSize),
		ptyToWs:      make(chan []byte, bufferSize),
		recoveryDone: make(chan struct{}),
		manager:      NewTerminalManager(),
	}
}

func waitRecovered(t *testing.T, done <-chan struct{}, cycle int) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatalf("recovery #%d did not complete: coordinator deadlocked", cycle)
	}
}

// TestPtyRecovery_ReadSideOnly reproduces the issue #351 deadlock: only the read side waits for recovery; before the fix the second reconnect blocked on the stale per-side completion signal.
func TestPtyRecovery_ReadSideOnly(t *testing.T) {
	s := newWshServer(t)
	pc := newTestPtyClient(t, s)
	defer pc.close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	recoveryChan := make(chan struct{}, 1)
	go pc.readFromWebsocket(ctx, cancel, recoveryChan)
	// writeToWebsocket is intentionally not started: nothing consumes a write-side completion signal.
	go pc.runRecoveryLoop(ctx, cancel, recoveryChan)

	for cycle := 0; cycle < 3; cycle++ {
		done := pc.awaitRecovery()
		s.killConn(t, cycle)
		waitRecovered(t, done, cycle+1)
	}
}

// TestPtyRecovery_WriteSideOnly is the mirror case: only the write side detects errors and waits for recovery.
func TestPtyRecovery_WriteSideOnly(t *testing.T) {
	s := newWshServer(t)
	pc := newTestPtyClient(t, s)
	defer pc.close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	recoveryChan := make(chan struct{}, 1)
	go pc.writeToWebsocket(ctx, cancel, recoveryChan)
	go pc.runRecoveryLoop(ctx, cancel, recoveryChan)

	for cycle := 0; cycle < 3; cycle++ {
		done := pc.awaitRecovery()
		s.killConn(t, cycle)
		// Keep feeding PTY output until the write side hits the broken connection (the first writes may still land in the OS buffer).
		deadline := time.After(10 * time.Second)
	feed:
		for {
			select {
			case <-done:
				break feed
			case pc.ptyToWs <- []byte("output"):
			case <-deadline:
				t.Fatalf("recovery #%d did not complete: coordinator deadlocked", cycle+1)
			}
		}
	}
}

// TestPtyRecovery_StormNoGoroutineLeak runs repeated reconnects with both sides active and verifies that goroutines do not accumulate and teardown completes.
func TestPtyRecovery_StormNoGoroutineLeak(t *testing.T) {
	s := newWshServer(t)

	baseline := runtime.NumGoroutine()

	pc := newTestPtyClient(t, s)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	recoveryChan := make(chan struct{}, 1)
	go pc.readFromWebsocket(ctx, cancel, recoveryChan)
	go pc.writeToWebsocket(ctx, cancel, recoveryChan)
	go pc.runRecoveryLoop(ctx, cancel, recoveryChan)

	const cycles = 5
	for cycle := 0; cycle < cycles; cycle++ {
		done := pc.awaitRecovery()
		s.killConn(t, cycle)
		waitRecovered(t, done, cycle+1)
	}

	if got := s.recoveryPosts.Load(); got < cycles {
		t.Fatalf("expected at least %d recovery posts, got %d", cycles, got)
	}

	// Tear down the session; close() unblocks the reader on the live conn.
	cancel()
	pc.close()

	// Drop test-infra keep-alive connections (recovery POSTs) so their transport goroutines do not distort the leak check.
	s.ts.Client().Transport.(*http.Transport).CloseIdleConnections()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if runtime.NumGoroutine() <= baseline+2 {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	buf := make([]byte, 1<<20)
	n := runtime.Stack(buf, true)
	t.Fatalf("goroutines grew after reconnect storm: baseline=%d now=%d\n%s", baseline, runtime.NumGoroutine(), buf[:n])
}

// trackedConn wraps a net.Conn to force write failures and observe Close.
type trackedConn struct {
	net.Conn
	failWrites atomic.Bool
	closed     atomic.Bool
}

func (c *trackedConn) Write(b []byte) (int, error) {
	if c.failWrites.Load() {
		return 0, errors.New("simulated write failure")
	}
	return c.Conn.Write(b)
}

func (c *trackedConn) Close() error {
	c.closed.Store(true)
	return c.Conn.Close()
}

// TestPtyClose_ClosesConnAfterWriteControlFailure verifies that close() releases the WebSocket connection even when the close handshake fails.
func TestPtyClose_ClosesConnAfterWriteControlFailure(t *testing.T) {
	s := newWshServer(t)

	var tracked *trackedConn
	dialer := websocket.Dialer{
		NetDial: func(network, addr string) (net.Conn, error) {
			c, err := net.Dial(network, addr)
			if err != nil {
				return nil, err
			}
			tracked = &trackedConn{Conn: c}
			return tracked, nil
		},
	}
	conn, _, err := dialer.Dial(s.wsURL(), nil)
	if err != nil {
		t.Fatal(err)
	}

	pc := &PtyClient{
		conn:      conn,
		sessionID: "close-test",
		manager:   NewTerminalManager(),
	}

	tracked.failWrites.Store(true)
	pc.close()

	if !tracked.closed.Load() {
		t.Fatal("close() did not close the websocket connection after WriteControl failure")
	}
}
