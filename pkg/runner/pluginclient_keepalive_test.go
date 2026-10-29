package runner_test

import (
	"bufio"
	"context"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
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

// dialPipe dials a WebSocket over an in-memory pipe and runs serve on the far
// end once the handshake is done, so the whole connection lives in a bubble.
func dialPipe(t *testing.T, serve func(peer net.Conn)) (*websocket.Conn, error) {
	client, server := net.Pipe()
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})

	go func() {
		r := bufio.NewReader(server)
		req, err := http.ReadRequest(r)
		if err != nil {
			return
		}
		sum := sha1.Sum([]byte(req.Header.Get("Sec-WebSocket-Key") + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
		_, _ = fmt.Fprintf(server, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n",
			base64.StdEncoding.EncodeToString(sum[:]))
		serve(server)
	}()

	dialer := websocket.Dialer{
		NetDialContext: func(context.Context, string, string) (net.Conn, error) { return client, nil },
	}
	conn, _, err := dialer.Dial("ws://alpacon.test/ws/", nil)
	return conn, err
}

// answerFirstPing pongs the first ping the client sends and then reads on
// without ever answering, as a link that drops traffic without a close does.
func answerFirstPing(peer net.Conn, answered chan<- time.Time) {
	for {
		var header [2]byte
		if _, err := io.ReadFull(peer, header[:]); err != nil {
			return
		}
		body := make([]byte, 4+int(header[1]&0x7f)) // client frames are masked and pings carry at most 125 bytes
		if _, err := io.ReadFull(peer, body); err != nil {
			return
		}
		if header[0]&0x0f == websocket.PingMessage {
			mask, payload := body[:4], body[4:]
			for i := range payload {
				payload[i] ^= mask[i%4]
			}
			_, _ = peer.Write(append([]byte{0x80 | websocket.PongMessage, byte(len(payload))}, payload...))
			answered <- time.Now()
			_, _ = io.Copy(io.Discard, peer)
			return
		}
	}
}

func TestPluginClient_RedialsAConnectionThatGoesSilentWithinTheKeepaliveTimeout(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		silentAt := make(chan time.Time, 1)
		redialAt := make(chan time.Time, 1)
		dials := 0

		wc := runner.NewWebsocketClient(nil, nil, nil)
		runner.SetDial(wc, func(context.Context, string, http.Header) (*websocket.Conn, error) {
			dials++
			if dials == 1 {
				return dialPipe(t, func(peer net.Conn) { answerFirstPing(peer, silentAt) })
			}
			if dials == 2 {
				redialAt <- time.Now()
			}
			return dialPipe(t, func(peer net.Conn) { _, _ = io.Copy(io.Discard, peer) })
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

		// 45s of keepalive timeout, then up to 10s of redial jitter.
		elapsed := redial.Sub(silent)
		assert.GreaterOrEqual(t, elapsed, 45*time.Second, "the plugin client redialled before the keepalive timeout ran out")
		assert.LessOrEqual(t, elapsed, 55*time.Second, "the plugin client redialled later than the keepalive timeout plus the redial jitter")
	})
}
