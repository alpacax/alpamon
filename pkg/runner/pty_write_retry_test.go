//go:build !windows

package runner

// Regression tests: a reconnect must not lose the chunk whose write was in
// flight when the connection dropped, and a recovery that cannot succeed
// must still end the write loop instead of retrying forever.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/alpacax/alpamon/v2/pkg/config"
	"github.com/alpacax/alpamon/v2/pkg/scheduler"
	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/require"
)

// TestPtyRecovery_ResendsFailedWriteAfterRecovery reproduces the chunk-loss
// bug: the first WriteMessage on the original connection fails, recovery
// swaps in a working connection, and the chunk whose write failed must be
// resent on it before the following chunk, arriving exactly once and in
// order.
func TestPtyRecovery_ResendsFailedWriteAfterRecovery(t *testing.T) {
	s := newWshServer(t)

	conn, tracked := dialTracked(t, s.wsURL())
	// Fails every write on this connection; recovery swaps pc.conn to a
	// fresh, untracked one before the retry, so only the pre-recovery write
	// actually goes through the failing path.
	tracked.failWrites.Store(true)

	pc := &PtyClient{
		conn:         conn,
		apiSession:   &scheduler.Session{BaseURL: s.ts.URL, Client: s.ts.Client()},
		sessionID:    "resend-test",
		wsToPty:      make(chan []byte, bufferSize),
		ptyToWs:      make(chan []byte, bufferSize),
		recoveryDone: make(chan struct{}),
		manager:      NewTerminalManager(),
	}
	defer pc.close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	recoveryChan := make(chan struct{}, 1)
	go pc.writeToWebsocket(ctx, cancel, recoveryChan)
	go pc.runRecoveryLoop(ctx, cancel, recoveryChan)

	done := pc.awaitRecovery()
	pc.ptyToWs <- []byte("chunk-A") // write fails on the tracked conn, triggering recovery
	waitRecovered(t, done, 1)

	pc.ptyToWs <- []byte("chunk-B") // next chunk, must follow chunk-A, not replace it

	require.Eventually(t, func() bool {
		return len(s.receivedMessages()) >= 2
	}, 5*time.Second, 20*time.Millisecond, "did not observe both chunks on the recovered connection")

	msgs := s.receivedMessages()
	require.Len(t, msgs, 2, "chunk-A must be resent exactly once, not dropped or duplicated")
	require.Equal(t, "chunk-A", string(msgs[0]), "the chunk whose write failed must be resent first")
	require.Equal(t, "chunk-B", string(msgs[1]), "the following chunk must arrive after the resend, in order")
}

// TestPtyRecovery_FailedRecoveryEndsWriteLoop checks the other side of the
// retry: when recovery itself cannot succeed, writeToWebsocket must still
// exit rather than loop forever waiting to resend.
func TestPtyRecovery_FailedRecoveryEndsWriteLoop(t *testing.T) {
	// recovery() builds the reconnect URL by concatenating
	// GlobalSettings.ServerURL with resp.websocket_url, so a relative
	// websocket_url is what the real server sends. Returning one with an
	// invalid percent-escape makes the concatenated URL fail url.Parse inside
	// validateWebSocketURL—recovery() wraps that in retry.Permanent, so it
	// fails deterministically on the first attempt instead of dialing
	// anything or waiting out maxRecoveryTimeout's backoff retries.
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	mux := http.NewServeMux()
	mux.HandleFunc("/ws/pty", func(w http.ResponseWriter, r *http.Request) {
		_, _ = upgrader.Upgrade(w, r, nil)
	})
	mux.HandleFunc(reconnectPtyWebsocketURL, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"websocket_url": "/ws/pty%zz"}`))
	})
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)

	prevServerURL := config.GlobalSettings.ServerURL
	config.GlobalSettings.ServerURL = ts.URL
	t.Cleanup(func() { config.GlobalSettings.ServerURL = prevServerURL })

	wsURL := strings.Replace(ts.URL, "http", "ws", 1) + "/ws/pty"
	conn, tracked := dialTracked(t, wsURL)
	tracked.failWrites.Store(true)

	pc := &PtyClient{
		conn:         conn,
		apiSession:   &scheduler.Session{BaseURL: ts.URL, Client: ts.Client()},
		sessionID:    "failed-recovery-test",
		wsToPty:      make(chan []byte, bufferSize),
		ptyToWs:      make(chan []byte, bufferSize),
		recoveryDone: make(chan struct{}),
		manager:      NewTerminalManager(),
	}
	defer pc.close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	recoveryChan := make(chan struct{}, 1)
	writeLoopDone := make(chan struct{})
	go func() {
		defer close(writeLoopDone)
		pc.writeToWebsocket(ctx, cancel, recoveryChan)
	}()
	go pc.runRecoveryLoop(ctx, cancel, recoveryChan)

	pc.ptyToWs <- []byte("will-fail") // write fails, recovery is requested and then permanently fails

	select {
	case <-writeLoopDone:
	case <-time.After(10 * time.Second):
		t.Fatal("writeToWebsocket kept retrying instead of exiting after a failed recovery")
	}

	require.Error(t, ctx.Err(), "a failed recovery must cancel the session context")
}
