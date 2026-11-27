package runner

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/alpacax/alpamon/v2/pkg/config"
	"github.com/alpacax/alpamon/v2/pkg/tunnel"
	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xtaci/smux"
)

func TestIsValidSessionID(t *testing.T) {
	tests := []struct {
		name      string
		sessionID string
		want      bool
	}{
		{name: "valid alphanumeric", sessionID: "session123", want: true},
		{name: "valid underscore", sessionID: "session_123", want: true},
		{name: "valid hyphen", sessionID: "session-123", want: true},
		{name: "invalid empty", sessionID: "", want: false},
		{name: "invalid slash", sessionID: "session/123", want: false},
		{name: "invalid backslash", sessionID: `session\123`, want: false},
		{name: "invalid traversal", sessionID: "../session", want: false},
		{name: "invalid dot sequence", sessionID: "a..b", want: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := IsValidSessionID(tc.sessionID)
			require.Equal(t, tc.want, got, "IsValidSessionID(%q)", tc.sessionID)
		})
	}
}

func TestGetHTTPStatusForHealth(t *testing.T) {
	tests := []struct {
		name   string
		status string
		want   int
	}{
		{name: "ready", status: "ready", want: 200},
		{name: "installing", status: "installing", want: 503},
		{name: "starting", status: "starting", want: 503},
		{name: "error maps to internal server error", status: "error", want: 500},
		{name: "unknown status maps to internal server error", status: "something-else", want: 500},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := getHTTPStatusForHealth(tc.status)
			require.Equal(t, tc.want, got, "getHTTPStatusForHealth(%q)", tc.status)
		})
	}
}

func TestBuildHealthResponseBody(t *testing.T) {
	t.Run("status only omits empty error", func(t *testing.T) {
		body := buildHealthResponseBody("ready", "")

		var decoded map[string]any
		require.NoError(t, json.Unmarshal([]byte(body), &decoded), "buildHealthResponseBody returned invalid JSON")
		require.Equal(t, "ready", decoded["status"])
		require.NotContains(t, decoded, "error", "error field should be omitted when empty")
	})

	t.Run("includes error field when provided", func(t *testing.T) {
		body := buildHealthResponseBody("error", "startup failed")

		var decoded map[string]any
		require.NoError(t, json.Unmarshal([]byte(body), &decoded), "buildHealthResponseBody returned invalid JSON")
		require.Equal(t, "error", decoded["status"])
		require.Equal(t, "startup failed", decoded["error"])
	})
}

func TestResolveTargetPort(t *testing.T) {
	for _, clientType := range []string{ClientTypeCLI, ClientTypeWeb, ClientTypeEditor} {
		for _, remote := range []string{"", "3000", "8080", "0", "65536", "abc"} {
			t.Run(clientType+"/"+remote, func(t *testing.T) {
				tc := &TunnelClient{clientType: clientType}
				tc.targetPort.Store(3000)
				port, err := tc.resolveTargetPort(remote)
				if clientType == ClientTypeEditor || remote == "" || remote == "3000" {
					require.NoError(t, err)
					assert.Equal(t, 3000, port)
				} else {
					require.Error(t, err)
					assert.Zero(t, port)
					if remote == "abc" {
						assert.NotContains(t, err.Error(), remote)
					}
				}
			})
		}
	}
}

func TestCloseAllActiveTunnels(t *testing.T) {
	t.Run("closes all tunnels and clears map", func(t *testing.T) {
		activeTunnelsMu.Lock()
		activeTunnels = make(map[string]*TunnelClient)
		activeTunnelsMu.Unlock()

		ctx1, cancel1 := context.WithCancel(context.Background())
		tc1 := &TunnelClient{sessionID: "s1", ctx: ctx1, cancel: cancel1}
		ctx2, cancel2 := context.WithCancel(context.Background())
		tc2 := &TunnelClient{sessionID: "s2", ctx: ctx2, cancel: cancel2}

		RegisterTunnel("s1", tc1)
		RegisterTunnel("s2", tc2)

		CloseAllActiveTunnels()

		activeTunnelsMu.RLock()
		remaining := len(activeTunnels)
		activeTunnelsMu.RUnlock()

		require.Equal(t, 0, remaining, "expected 0 active tunnels after CloseAll")
		require.Error(t, ctx1.Err(), "expected tc1 context to be cancelled")
		require.Error(t, ctx2.Err(), "expected tc2 context to be cancelled")
	})

	t.Run("safe on empty map", func(t *testing.T) {
		activeTunnelsMu.Lock()
		activeTunnels = make(map[string]*TunnelClient)
		activeTunnelsMu.Unlock()

		CloseAllActiveTunnels() // should not panic
	})

	t.Run("double close is safe", func(t *testing.T) {
		activeTunnelsMu.Lock()
		activeTunnels = make(map[string]*TunnelClient)
		activeTunnelsMu.Unlock()

		ctx, cancel := context.WithCancel(context.Background())
		tc := &TunnelClient{sessionID: "s3", ctx: ctx, cancel: cancel}
		RegisterTunnel("s3", tc)

		CloseAllActiveTunnels()
		tc.Close() // second close should not panic (sync.Once)
	})
}

const smuxFrameWithHeader = config.SmuxMaxFrameSize + smuxHeaderSize

type writeCountingConn struct {
	net.Conn
	writes *atomic.Int64
}

func (c *writeCountingConn) Write(p []byte) (int, error) {
	if len(p) > 0 {
		c.writes.Add(1)
	}
	return c.Conn.Write(p)
}

func dialTunnelServer(t testing.TB) (*tunnel.WebSocketConn, *atomic.Int64, <-chan *websocket.Conn) {
	t.Helper()
	serverConns := make(chan *websocket.Conn, 1)
	upgrader := websocket.Upgrader{ReadBufferSize: 4096, WriteBufferSize: 4096}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		serverConns <- c
	}))
	t.Cleanup(srv.Close)

	writes := &atomic.Int64{}
	dialer := newTunnelDialer()
	var nd net.Dialer
	dialer.NetDialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		c, err := nd.DialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		return &writeCountingConn{Conn: c, writes: writes}, nil
	}
	conn, _, err := dialer.Dial("ws"+strings.TrimPrefix(srv.URL, "http"), nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	return tunnel.NewWebSocketConn(conn), writes, serverConns
}

func TestTunnelDialerWritesFullSmuxFrameAsOneSocketWrite(t *testing.T) {
	wc, writes, serverConns := dialTunnelServer(t)
	server := <-serverConns
	t.Cleanup(func() { _ = server.Close() })
	payload := make([]byte, smuxFrameWithHeader)
	for i := range payload {
		payload[i] = byte(i)
	}
	writes.Store(0)

	n, err := wc.Write(payload)
	require.NoError(t, err)
	require.Equal(t, len(payload), n)

	assert.EqualValues(t, 1, writes.Load())
	_ = server.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, got, err := server.ReadMessage()
	require.NoError(t, err)
	assert.Equal(t, payload, got)
}

func BenchmarkTunnelWrite(b *testing.B) {
	wc, writes, serverConns := dialTunnelServer(b)
	server := <-serverConns
	b.Cleanup(func() { _ = server.Close() })
	go func() {
		for {
			if _, _, err := server.NextReader(); err != nil {
				return
			}
		}
	}()
	payload := make([]byte, smuxFrameWithHeader)
	writes.Store(0)

	b.ReportAllocs()
	b.SetBytes(int64(len(payload)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := wc.Write(payload); err != nil {
			b.Fatal(err)
		}
	}
	b.StopTimer()
	b.ReportMetric(float64(writes.Load())/float64(b.N), "sockwrites/op")
}

// registeredTunnel builds a CLI tunnel aimed at the configured server and
// registers it, as handleOpenTunnel does before Open.
func registeredTunnel(t *testing.T, sessionID string, startRelay func() error) *TunnelClient {
	t.Helper()
	tc := NewTunnelClient(sessionID, ClientTypeCLI, 22, "", "", "/ws/tunnel/"+sessionID+"/")
	tc.startRelay = startRelay
	require.True(t, RegisterTunnel(sessionID, tc))
	t.Cleanup(func() { _ = CloseTunnel(sessionID) })
	return tc
}

func relayMustNotStart() error { return errors.New("the relay must not start") }

// newHeldHandshakeServer never answers the upgrade; reached closes once a
// request has arrived, so the dial is known to be waiting on the handshake.
func newHeldHandshakeServer(t *testing.T) (srv *httptest.Server, reached <-chan struct{}) {
	t.Helper()
	arrived := make(chan struct{})
	var once sync.Once
	release := make(chan struct{})
	srv = httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		once.Do(func() { close(arrived) })
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	t.Cleanup(func() {
		close(release)
		srv.Close()
	})
	return srv, arrived
}

func waitFor(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for %s", what)
	}
}

func TestTunnelOpen_ConnectsAndStartsTheRelay(t *testing.T) {
	srv, _ := newSocketTargetServer(t)
	setServerURL(t, srv.URL)
	relayStarted := false
	tc := registeredTunnel(t, "open-ok", func() error {
		relayStarted = true
		return nil
	})

	err := tc.Open(t.Context())

	require.NoError(t, err)
	assert.True(t, relayStarted)
	assert.NotNil(t, tc.session)
	got, registered := GetActiveTunnel("open-ok")
	assert.True(t, registered)
	assert.Same(t, tc, got)
}

func TestTunnelOpen_ReportsARelayThatCannotStartAndUnregisters(t *testing.T) {
	srv, _ := newSocketTargetServer(t)
	setServerURL(t, srv.URL)
	tc := registeredTunnel(t, "relay-fails", func() error {
		return errors.New("tunnel daemon not ready")
	})

	err := tc.Open(t.Context())

	require.EqualError(t, err, "failed to start tunnel relay: tunnel daemon not ready")
	_, registered := GetActiveTunnel("relay-fails")
	assert.False(t, registered)
	assert.Error(t, tc.ctx.Err(), "a failed open must close the tunnel")
}

func TestTunnelOpen_ReportsTheStatusOfARefusedHandshake(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "forbidden", http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)
	setServerURL(t, srv.URL)
	tc := registeredTunnel(t, "handshake-refused", relayMustNotStart)

	err := tc.Open(t.Context())

	require.EqualError(t, err, "failed to connect to tunnel server: websocket: bad handshake (HTTP 403)")
	var handshake *handshakeError
	require.ErrorAs(t, err, &handshake)
	assert.Equal(t, http.StatusForbidden, handshake.StatusCode)
	_, registered := GetActiveTunnel("handshake-refused")
	assert.False(t, registered)
}

func TestTunnelOpen_IsCanceledByACloseTunnelDuringTheHandshake(t *testing.T) {
	srv, reached := newHeldHandshakeServer(t)
	setServerURL(t, srv.URL)
	tc := registeredTunnel(t, "closed-while-dialing", relayMustNotStart)
	opened := make(chan error, 1)
	go func() { opened <- tc.Open(t.Context()) }()
	waitFor(t, reached, "the dial to reach the handshake")

	require.NoError(t, CloseTunnel("closed-while-dialing"))

	select {
	case err := <-opened:
		require.ErrorIs(t, err, ErrTunnelClosedWhileOpening)
	case <-time.After(5 * time.Second):
		t.Fatal("Open kept waiting on the handshake after closetunnel")
	}
	_, registered := GetActiveTunnel("closed-while-dialing")
	assert.False(t, registered)
}

func TestTunnelOpen_StopsTheHandshakeWhenTheCommandContextEnds(t *testing.T) {
	srv, _ := newHeldHandshakeServer(t)
	setServerURL(t, srv.URL)
	tc := registeredTunnel(t, "command-deadline", relayMustNotStart)
	ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()

	err := tc.Open(ctx)

	require.Error(t, err)
	assert.True(t, errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded),
		"want the command deadline, or gorilla's i/o timeout reporting it first, got %v", err)
	assert.Less(t, time.Since(start), 5*time.Second)
	_, registered := GetActiveTunnel("command-deadline")
	assert.False(t, registered)
}

func TestTunnelOpen_DialsNothingAfterTheTunnelWasClosed(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	setServerURL(t, "http://"+ln.Addr().String())
	tc := registeredTunnel(t, "closed-before-open", relayMustNotStart)
	tc.Close()

	err = tc.Open(t.Context())

	require.ErrorIs(t, err, ErrTunnelClosedWhileOpening)
	// A loopback connect is queued for Accept by the time it returns, so any dial Open made is already here.
	require.NoError(t, ln.(*net.TCPListener).SetDeadline(time.Now().Add(100*time.Millisecond)))
	conn, acceptErr := ln.Accept()
	if conn != nil {
		_ = conn.Close()
	}
	assert.ErrorIs(t, acceptErr, os.ErrDeadlineExceeded, "Open dialed a closed tunnel")
	assert.Nil(t, tc.session)
}

func TestTunnelOpen_ReportsACloseThatArrivesWhileTheRelayStarts(t *testing.T) {
	srv, _ := newSocketTargetServer(t)
	setServerURL(t, srv.URL)
	tc := registeredTunnel(t, "closed-during-relay", func() error {
		require.NoError(t, CloseTunnel("closed-during-relay"))
		return nil
	})

	err := tc.Open(t.Context())

	require.ErrorIs(t, err, ErrTunnelClosedWhileOpening)
	_, registered := GetActiveTunnel("closed-during-relay")
	assert.False(t, registered)
}

func TestTunnelOpen_ReportsACloseThatFailsTheRelayStart(t *testing.T) {
	srv, _ := newSocketTargetServer(t)
	setServerURL(t, srv.URL)
	var tc *TunnelClient
	tc = registeredTunnel(t, "closed-failing-relay", func() error {
		require.NoError(t, CloseTunnel("closed-failing-relay"))
		return fmt.Errorf("tunnel session closed while waiting for daemon socket: %w", tc.ctx.Err()) // as startTunnelRelay reports it
	})

	err := tc.Open(t.Context())

	require.ErrorIs(t, err, ErrTunnelClosedWhileOpening)
	_, registered := GetActiveTunnel("closed-failing-relay")
	assert.False(t, registered)
}

func TestTunnelOpen_ReportsATunnelUnregisteredButNotYetClosed(t *testing.T) {
	srv, _ := newSocketTargetServer(t)
	setServerURL(t, srv.URL)
	tc := registeredTunnel(t, "unregistered-during-relay", func() error {
		activeTunnelsMu.Lock() // CloseTunnel's delete, before its Close sets closed
		delete(activeTunnels, "unregistered-during-relay")
		activeTunnelsMu.Unlock()
		return nil
	})

	err := tc.Open(t.Context())

	require.ErrorIs(t, err, ErrTunnelClosedWhileOpening)
	assert.Error(t, tc.ctx.Err(), "a failed open must close the tunnel")
}

func TestTunnelOpen_ReportsACommandContextThatEndsWhileTheRelayStarts(t *testing.T) {
	srv, _ := newSocketTargetServer(t)
	setServerURL(t, srv.URL)
	ctx, cancel := context.WithCancel(t.Context())
	tc := registeredTunnel(t, "canceled-during-relay", func() error {
		cancel()
		return nil
	})

	err := tc.Open(ctx)

	require.ErrorIs(t, err, context.Canceled)
	_, registered := GetActiveTunnel("canceled-during-relay")
	assert.False(t, registered)
	assert.Error(t, tc.ctx.Err(), "a failed open must close the tunnel")
}

func TestTunnelServe_UnregistersWhenTheServerEndsTheSession(t *testing.T) {
	upgrader := websocket.Upgrader{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		_ = conn.Close()
	}))
	t.Cleanup(srv.Close)
	setServerURL(t, srv.URL)
	tc := registeredTunnel(t, "server-hangs-up", func() error { return nil })
	require.NoError(t, tc.Open(t.Context()))
	served := make(chan struct{})

	go func() {
		tc.Serve()
		close(served)
	}()

	waitFor(t, served, "Serve to return after the server closed the session")
	_, registered := GetActiveTunnel("server-hangs-up")
	assert.False(t, registered)
	assert.Error(t, tc.ctx.Err())
}

func TestTunnelUnregisterAndClose_LeavesANewerTunnelUnderTheSameID(t *testing.T) {
	stale := NewTunnelClient("reused-id", ClientTypeCLI, 22, "", "", "/ws/tunnel/reused-id/")
	newer := NewTunnelClient("reused-id", ClientTypeCLI, 22, "", "", "/ws/tunnel/reused-id/")
	require.True(t, RegisterTunnel("reused-id", newer))
	t.Cleanup(func() { _ = CloseTunnel("reused-id") })

	stale.unregisterAndClose()

	got, registered := GetActiveTunnel("reused-id")
	assert.True(t, registered)
	assert.Same(t, newer, got)
	assert.Error(t, stale.ctx.Err())
	assert.NoError(t, newer.ctx.Err())
}

func TestTunnelServe_UnregistersWhenTheStreamLoopPanics(t *testing.T) {
	tc := registeredTunnel(t, "panicking-session", relayMustNotStart)
	logs := captureLogs(t)

	tc.serve(func() { panic("injected stream loop panic") })

	_, registered := GetActiveTunnel("panicking-session")
	assert.False(t, registered)
	assert.ErrorIs(t, tc.ctx.Err(), context.Canceled)
	assert.Contains(t, logs.String(), `"goroutine":"tunnel session"`)
}

func TestTunnelServeStream_FreesItsSlotsWhenTheHandlerPanics(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		logs := captureLogs(t)
		tc := &TunnelClient{sessionID: "s", streamSem: make(chan struct{}, 1)}
		tc.streamSem <- struct{}{}
		globalStreamSem <- struct{}{}
		globalBefore := len(globalStreamSem)

		tc.serveStream(nil, func(*smux.Stream) { panic("injected stream handler panic") })

		synctest.Wait()
		assert.Empty(t, tc.streamSem)
		assert.Len(t, globalStreamSem, globalBefore-1)
		assert.Contains(t, logs.String(), `"goroutine":"tunnel stream"`)
	})
}
