//go:build !windows

package runner

// Websh pty connection liveness: the agent pings the pty WebSocket and, from
// the dial on, recovers a connection that stays silent for keepaliveTimeout.

import (
	"context"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alpacax/alpamon/v2/pkg/scheduler"
	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// startKeepalivePty dials s and installs the conn the way a session does, then
// runs the Websh read loop and the recovery loop. No PTY or shell is started:
// liveness and recovery do not need them. stop ends the session and waits for
// both loops to return.
func startKeepalivePty(t *testing.T, s *wshServer) (pc *PtyClient, ctx context.Context, stop func()) {
	t.Helper()
	pc = &PtyClient{
		apiSession:   &scheduler.Session{BaseURL: s.ts.URL, Client: s.ts.Client()},
		sessionID:    "keepalive-test",
		wsToPty:      make(chan []byte, bufferSize),
		ptyToWs:      make(chan []byte, bufferSize),
		recoveryDone: make(chan struct{}),
		manager:      NewTerminalManager(),
	}

	ctx, cancel := context.WithCancel(context.Background())
	conn, _, err := websocket.DefaultDialer.Dial(s.wsURL(), nil)
	require.NoError(t, err)
	pc.installConn(ctx, conn)

	var wg sync.WaitGroup
	recoveryChan := make(chan struct{}, 1)
	wg.Add(2)
	go func() { defer wg.Done(); pc.readFromWebsocket(ctx, cancel, recoveryChan) }()
	go func() { defer wg.Done(); pc.runRecoveryLoop(ctx, cancel, recoveryChan) }()

	stop = sync.OnceFunc(func() {
		cancel()
		pc.close()
		done := make(chan struct{})
		go func() { wg.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("the Websh loops did not return after the session ended")
		}
	})
	t.Cleanup(stop)
	return pc, ctx, stop
}

// ptyPingGoroutines counts the ping goroutines that installConn started and that are still running.
func ptyPingGoroutines() int {
	buf := make([]byte, 1<<20)
	for {
		n := runtime.Stack(buf, true)
		if n < len(buf) {
			return strings.Count(string(buf[:n]), "created by github.com/alpacax/alpamon/v2/pkg/runner.(*PtyClient).installConn")
		}
		buf = make([]byte, 2*len(buf))
	}
}

func TestPtyKeepalive_SilentPeerEntersRecovery(t *testing.T) {
	// Scaled-down timings: 150 ms pings, a 600 ms silence limit.
	shrinkKeepalive(t, 150*time.Millisecond, 600*time.Millisecond, 0)

	silentAt := make(chan time.Time, 1)
	redialAt := make(chan time.Time, 1)
	resume := make(chan struct{})
	releaseResume := sync.OnceFunc(func() { close(resume) })
	t.Cleanup(releaseResume)

	s := newWshServerWith(t, func(n int, c *websocket.Conn) {
		if n > 0 {
			redialAt <- time.Now()
			_ = readUntilError(c)
			return
		}
		// Answer the first ping, then stop reading altogether: the socket
		// stays up but nothing comes back, as on a silently dropped path.
		answered := false
		c.SetPingHandler(func(data string) error {
			if answered {
				return nil
			}
			answered = true
			_ = c.WriteControl(websocket.PongMessage, []byte(data), time.Now().Add(time.Second))
			silentAt <- time.Now()
			<-resume
			return nil
		})
		_ = readUntilError(c)
	})
	_, ctx, _ := startKeepalivePty(t, s)

	var silent, redial time.Time
	select {
	case silent = <-silentAt:
	case <-time.After(5 * time.Second):
		t.Fatal("the agent never pinged the Websh channel")
	}
	select {
	case redial = <-redialAt:
	case <-time.After(5 * time.Second):
		t.Fatal("the agent never reconnected the Websh channel after it went silent")
	}

	elapsed := redial.Sub(silent)
	assert.GreaterOrEqual(t, elapsed, keepaliveTimeout*3/4, "the agent reconnected before keepaliveTimeout had run out")
	assert.LessOrEqual(t, elapsed, keepaliveTimeout+time.Second, "the agent reconnected well after keepaliveTimeout")
	assert.EqualValues(t, 1, s.recoveryPosts.Load(), "a silent channel must go through recovery exactly once")
	require.NoError(t, ctx.Err(), "a silent channel must be recovered, not end the shell")
}

func TestPtyKeepalive_PeerAnsweringPingsStaysUp(t *testing.T) {
	shrinkKeepalive(t, 100*time.Millisecond, 800*time.Millisecond, 0)

	var pings atomic.Int32
	s := newWshServerWith(t, func(_ int, c *websocket.Conn) {
		c.SetPingHandler(func(data string) error {
			pings.Add(1)
			return c.WriteControl(websocket.PongMessage, []byte(data), time.Now().Add(time.Second))
		})
		_ = readUntilError(c)
	})
	pc, ctx, _ := startKeepalivePty(t, s)
	first, ka := pc.getConnState()

	// A silent shell: nothing crosses the channel but pings and pongs, for well past twice the limit.
	time.Sleep(keepaliveTimeout*2 + keepaliveTimeout/2)

	assert.True(t, ka.pongSeen.Load(), "the peer's pongs never reached the agent")
	assert.GreaterOrEqual(t, pings.Load(), int32(5), "the agent did not keep pinging")
	assert.Zero(t, s.recoveryPosts.Load(), "a channel whose peer answers pings must not be recovered")
	assert.Same(t, first, pc.getConn(), "a channel whose peer answers pings must not be replaced")
	require.NoError(t, ctx.Err(), "a channel whose peer answers pings must not end the shell")
}

func TestPtyKeepalive_PeerFramesKeepChannelUp(t *testing.T) {
	shrinkKeepalive(t, 100*time.Millisecond, 800*time.Millisecond, 0)

	s := newWshServerWith(t, func(_ int, c *websocket.Conn) {
		// Answer the first ping only, then keep the channel alive with data
		// frames alone once the pongs stop, as a busy session does.
		var answered atomic.Bool
		c.SetPingHandler(func(data string) error {
			if answered.Swap(true) {
				return nil
			}
			return c.WriteControl(websocket.PongMessage, []byte(data), time.Now().Add(time.Second))
		})
		done := make(chan struct{})
		go func() {
			ticker := time.NewTicker(keepaliveTimeout / 4)
			defer ticker.Stop()
			for {
				select {
				case <-done:
					return
				case <-ticker.C:
					if err := c.WriteMessage(websocket.BinaryMessage, []byte("input")); err != nil {
						return
					}
				}
			}
		}()
		_ = readUntilError(c)
		close(done)
	})
	pc, ctx, _ := startKeepalivePty(t, s)
	first, ka := pc.getConnState()

	time.Sleep(keepaliveTimeout*2 + keepaliveTimeout/2)

	assert.True(t, ka.pongSeen.Load(), "the first pong never reached the agent")
	assert.NotEmpty(t, pc.wsToPty, "the peer's frames never reached the PTY side")
	assert.Zero(t, s.recoveryPosts.Load(), "frames from the peer must keep the read deadline from expiring")
	assert.Same(t, first, pc.getConn(), "a channel carrying frames must not be replaced")
	require.NoError(t, ctx.Err(), "a channel carrying frames must not end the shell")
}

func TestPtyKeepalive_RecoveryStopsReplacedPings(t *testing.T) {
	shrinkKeepalive(t, 20*time.Millisecond, time.Second, 0)

	s := newWshServer(t)
	pc, _, stop := startKeepalivePty(t, s)

	require.Eventually(t, func() bool { return ptyPingGoroutines() == 1 }, 5*time.Second, 10*time.Millisecond,
		"installConn did not start exactly one ping goroutine")

	const cycles = 3
	for cycle := range cycles {
		done := pc.awaitRecovery()
		s.killConn(t, cycle)
		waitRecovered(t, done, cycle+1)
		require.Eventually(t, func() bool { return ptyPingGoroutines() == 1 }, 5*time.Second, 10*time.Millisecond,
			"recovery #%d left the replaced connection's ping goroutine running", cycle+1)
	}

	stop()
	require.Eventually(t, func() bool { return ptyPingGoroutines() == 0 }, 5*time.Second, 10*time.Millisecond,
		"the ping goroutine outlived the session")
}

func TestPtyKeepalive_SilentFromDialEntersRecovery(t *testing.T) {
	shrinkKeepalive(t, 150*time.Millisecond, 600*time.Millisecond, 0)

	acceptedAt := make(chan time.Time, 1)
	redialAt := make(chan time.Time, 1)
	s := newWshServerWith(t, func(n int, c *websocket.Conn) {
		if n > 0 {
			redialAt <- time.Now()
			_ = readUntilError(c)
			return
		}
		// Withhold every pong, the first included, and send nothing: the
		// path went silent right after the dial.
		c.SetPingHandler(func(string) error { return nil })
		acceptedAt <- time.Now()
		_ = readUntilError(c)
	})
	_, ctx, _ := startKeepalivePty(t, s)

	var accepted, redial time.Time
	select {
	case accepted = <-acceptedAt:
	case <-time.After(5 * time.Second):
		t.Fatal("the Websh channel was never accepted")
	}
	select {
	case redial = <-redialAt:
	case <-time.After(5 * time.Second):
		t.Fatal("the agent never reconnected a Websh channel that was silent from the dial")
	}

	elapsed := redial.Sub(accepted)
	assert.GreaterOrEqual(t, elapsed, keepaliveTimeout*3/4, "the agent reconnected before keepaliveTimeout had run out")
	assert.LessOrEqual(t, elapsed, keepaliveTimeout+time.Second, "the agent reconnected well after keepaliveTimeout")
	assert.EqualValues(t, 1, s.recoveryPosts.Load(), "a channel silent from the dial must go through recovery exactly once")
	require.NoError(t, ctx.Err(), "a channel silent from the dial must be recovered, not end the shell")
}

func TestPtyKeepalive_PeerIgnoringPingsStaysUpOnFrames(t *testing.T) {
	shrinkKeepalive(t, 100*time.Millisecond, 800*time.Millisecond, 0)

	s := newWshServerWith(t, func(_ int, c *websocket.Conn) {
		// Never answer a ping; keep the channel alive with data frames alone.
		c.SetPingHandler(func(string) error { return nil })
		done := make(chan struct{})
		go func() {
			ticker := time.NewTicker(keepaliveTimeout / 4)
			defer ticker.Stop()
			for {
				select {
				case <-done:
					return
				case <-ticker.C:
					if err := c.WriteMessage(websocket.BinaryMessage, []byte("input")); err != nil {
						return
					}
				}
			}
		}()
		_ = readUntilError(c)
		close(done)
	})
	pc, ctx, _ := startKeepalivePty(t, s)
	first, ka := pc.getConnState()

	time.Sleep(keepaliveTimeout*2 + keepaliveTimeout/2)

	assert.False(t, ka.pongSeen.Load(), "the peer answered a ping it was set to ignore")
	assert.NotEmpty(t, pc.wsToPty, "the peer's frames never reached the PTY side")
	assert.Zero(t, s.recoveryPosts.Load(), "frames from a peer that ignores pings must keep the channel up")
	assert.Same(t, first, pc.getConn(), "a channel carrying frames must not be replaced")
	require.NoError(t, ctx.Err(), "a channel carrying frames must not end the shell")
}
