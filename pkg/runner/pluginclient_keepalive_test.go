package runner_test

import (
	"context"
	"io"
	"net"
	"net/http"
	"testing"
	"testing/synctest"
	"time"

	"github.com/alpacax/alpamon/v2/pkg/pluginclient"
	"github.com/alpacax/alpamon/v2/pkg/runner"
	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/assert"
)

// answerFirstPing pongs the first ping the client sends and then reads on
// without ever answering, as a link that drops traffic without a close does.
func answerFirstPing(peer net.Conn, answered chan<- time.Time) {
	for {
		var header [2]byte
		if _, err := io.ReadFull(peer, header[:]); err != nil {
			return
		}
		// Client frames are masked and pings carry at most 125 bytes.
		body := make([]byte, 4+int(header[1]&0x7f))
		if _, err := io.ReadFull(peer, body); err != nil {
			return
		}
		if header[0]&0x0f == websocket.PingMessage {
			mask, payload := body[:4], body[4:]
			for i := range payload {
				payload[i] ^= mask[i%4]
			}
			pong := append([]byte{0x80 | websocket.PongMessage, byte(len(payload))}, payload...)
			_, _ = peer.Write(pong)
			answered <- time.Now()
			_, _ = io.Copy(io.Discard, peer)
			return
		}
	}
}

// Lives in runner_test for SetDial: the in-memory dial keeps the 45s keepalive
// inside a synctest bubble.
func TestPluginClient_RedialsAConnectionThatGoesSilentWithinTheKeepaliveTimeout(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		silentAt := make(chan time.Time, 1)
		redialAt := make(chan time.Time, 1)
		dials := 0

		wc := runner.NewWebsocketClient(nil, nil, nil)
		runner.SetDial(wc, func(context.Context, string, http.Header) (*websocket.Conn, error) {
			dials++
			if dials == 1 {
				return runner.DialPipe(t, func(peer net.Conn) { answerFirstPing(peer, silentAt) })
			}
			if dials == 2 {
				redialAt <- time.Now()
			}
			return runner.DialPipe(t, func(peer net.Conn) { _, _ = io.Copy(io.Discard, peer) })
		})
		c := &pluginclient.Client{WsClient: wc}

		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() {
			defer close(done)
			c.RunForever(ctx)
		}()
		t.Cleanup(func() {
			cancel()
			wc.Close()
			<-done
		})

		var silent, redial time.Time
		select {
		case silent = <-silentAt:
		case <-time.After(time.Minute):
			t.Fatal("the plugin client never pinged its connection")
		}
		select {
		case redial = <-redialAt:
		case <-time.After(time.Hour):
			t.Fatal("the plugin client never redialled a connection that went silent")
		}

		// Pins the 45s contract on purpose: the keepalive timeout, then up to 10s
		// of redial jitter.
		elapsed := redial.Sub(silent)
		assert.GreaterOrEqual(t, elapsed, 45*time.Second,
			"the plugin client redialled before the keepalive timeout ran out")
		assert.LessOrEqual(t, elapsed, 55*time.Second,
			"the plugin client redialled later than the keepalive timeout plus the redial jitter")
	})
}
