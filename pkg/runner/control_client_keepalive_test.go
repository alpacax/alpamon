package runner

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alpacax/alpamon/v2/pkg/config"
	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func useControlWSPath(t *testing.T, url string) {
	t.Helper()
	orig := config.GlobalSettings.ControlWSPath
	config.GlobalSettings.ControlWSPath = url
	t.Cleanup(func() { config.GlobalSettings.ControlWSPath = orig })
}

// startControlRunForever runs the control read loop and registers a cleanup
// that cancels it, closes the client, and waits for the loop to return.
func startControlRunForever(t *testing.T, cc *ControlClient) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		cc.RunForever(ctx)
	}()

	t.Cleanup(sync.OnceFunc(func() {
		cancel()
		cc.Close()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("control RunForever did not return after cancel and Close")
		}
	}))
}

func TestControlRunForever_RedialsAPeerThatStopsAnsweringPings(t *testing.T) {
	shrinkKeepalive(t, 50*time.Millisecond, 300*time.Millisecond, 10*time.Millisecond)

	redialed := make(chan struct{}, 1)
	resume := make(chan struct{})
	releaseResume := sync.OnceFunc(func() { close(resume) })
	t.Cleanup(releaseResume)
	firstReadEnd := make(chan struct{})
	var closeFrame atomic.Bool
	url := newKeepaliveServer(t, func(n int, c *websocket.Conn) {
		if n > 0 {
			redialed <- struct{}{}
			_ = readUntilError(c)
			return
		}
		// Answer the first ping, then stop reading: the socket stays up but silent.
		answered := false
		c.SetPingHandler(func(data string) error {
			if answered {
				return nil
			}
			answered = true
			_ = c.WriteControl(websocket.PongMessage, []byte(data), time.Now().Add(time.Second))
			<-resume
			return nil
		})
		c.SetCloseHandler(func(int, string) error {
			closeFrame.Store(true)
			return nil
		})
		_ = readUntilError(c)
		close(firstReadEnd)
	})
	useControlWSPath(t, url)

	cc := &ControlClient{connectBackoff: newAuthBackoff(minConnectInterval, maxConnectInterval)}
	startControlRunForever(t, cc)

	select {
	case <-redialed:
	case <-time.After(3 * time.Second):
		t.Fatal("the control client never redialled after the server went silent")
	}

	// Let the silent side read what the client left behind: its pings, then the end of the socket.
	releaseResume()
	select {
	case <-firstReadEnd:
	case <-time.After(5 * time.Second):
		t.Fatal("the dropped control connection was never closed")
	}
	assert.False(t, closeFrame.Load(), "the control client sent a close frame on a keepalive timeout")
}

func TestControlRunForever_KeepsTheLongTimeoutForAPeerThatNeverAnswersPings(t *testing.T) {
	shrinkKeepalive(t, 20*time.Millisecond, 100*time.Millisecond, 10*time.Millisecond)

	var connections, pings atomic.Int32
	url := newKeepaliveServer(t, func(_ int, c *websocket.Conn) {
		connections.Add(1)
		c.SetPingHandler(func(string) error {
			pings.Add(1)
			return nil
		})
		_ = readUntilError(c)
	})
	useControlWSPath(t, url)

	cc := &ControlClient{connectBackoff: newAuthBackoff(minConnectInterval, maxConnectInterval)}
	startControlRunForever(t, cc)
	require.Eventually(t, func() bool { return pings.Load() > 0 }, 3*time.Second, 10*time.Millisecond,
		"the control client never pinged")

	time.Sleep(5 * keepaliveTimeout)

	assert.Equal(t, int32(1), connections.Load(), "the control client redialled although no ping was ever answered")
}
