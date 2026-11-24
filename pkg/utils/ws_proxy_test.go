package utils

import (
	"bytes"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// wsProxyChildWant is what the re-executed binary expects WebsocketProxy to
// return: a proxy URL, or "direct".
const wsProxyChildWant = "ALPAMON_TEST_WS_PROXY_WANT"

// gorilla/websocket hands its Proxy func the dial URL with ws/wss turned into
// http/https, so the requests here use those schemes.
func TestWebsocketProxy_ProxyEnvironment(t *testing.T) {
	if want := os.Getenv(wsProxyChildWant); want != "" {
		var logs bytes.Buffer
		log.Logger = zerolog.New(&logs)
		req, err := http.NewRequest(http.MethodGet, os.Getenv(proxyChildTarget), nil)
		require.NoError(t, err)

		for range 2 {
			proxyURL, err := WebsocketProxy(req)
			require.NoError(t, err)
			if want == "direct" {
				assert.Nil(t, proxyURL)
			} else if assert.NotNil(t, proxyURL) {
				assert.Equal(t, want, proxyURL.String())
			}
		}

		warnings := strings.Count(logs.String(), `"level":"warn"`)
		if want == "direct" && os.Getenv("HTTPS_PROXY") != "" {
			assert.Equal(t, 1, warnings, "one warning per process: %s", logs.String())
			assert.Contains(t, logs.String(), "HTTPS_PROXY uses the https scheme, which WebSocket connections do not support; WebSocket connections dial directly.")
			for _, secret := range []string{"user", "secret", "proxy.example"} {
				assert.NotContains(t, logs.String(), secret)
			}
		} else {
			assert.Zero(t, warnings, logs.String())
		}
		return
	}

	tests := []struct {
		name string
		env  []string
		want string
	}{
		{"https proxy dials directly with a warning", []string{"HTTPS_PROXY=https://user:secret@proxy.example:3128"}, "direct"},
		{"http proxy", []string{"HTTPS_PROXY=http://proxy.example:3128"}, "http://proxy.example:3128"},
		{"socks5 proxy", []string{"HTTPS_PROXY=socks5://proxy.example:1080"}, "socks5://proxy.example:1080"},
		{"no proxy environment", nil, "direct"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := append([]string{wsProxyChildWant + "=" + tt.want}, tt.env...)
			runProxyChild(t, "TestWebsocketProxy_ProxyEnvironment", "https://alpacon.example.test/ws/servers/backhaul/", env...)
		})
	}
}

func TestWebsocketProxy_PassesResolverErrorsThrough(t *testing.T) {
	p := &websocketProxy{resolve: func(*http.Request) (*url.URL, error) { return nil, assert.AnError }}
	req, err := http.NewRequest(http.MethodGet, "https://alpacon.example.test/", nil)
	require.NoError(t, err)

	proxyURL, err := p.proxy(req)
	assert.Nil(t, proxyURL)
	assert.ErrorIs(t, err, assert.AnError)
}

// silentSOCKS5 runs a SOCKS5 proxy that grants every CONNECT, then never answers
// through the tunnel, like a backhaul that took the connection and went quiet.
func silentSOCKS5(t *testing.T) *url.URL {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			t.Cleanup(func() { _ = c.Close() })
			go func() {
				buf := make([]byte, 262)
				if _, err := io.ReadFull(c, buf[:2]); err != nil { // version, method count
					return
				}
				if _, err := io.ReadFull(c, buf[:buf[1]]); err != nil {
					return
				}
				_, _ = c.Write([]byte{5, 0})                       // no authentication
				if _, err := io.ReadFull(c, buf[:5]); err != nil { // version, CONNECT, reserved, type, first address byte
					return
				}
				rest := map[byte]int{1: 3 + 2, 3: int(buf[4]) + 2, 4: 15 + 2}[buf[3]]
				if _, err := io.ReadFull(c, buf[:rest]); err != nil {
					return
				}
				_, _ = c.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 80})
				_, _ = io.Copy(io.Discard, c)
			}()
		}
	}()
	return &url.URL{Scheme: "socks5", Host: ln.Addr().String()}
}

func TestBoundWebsocketDial_HandshakeTimeoutCoversTheUpgradeBehindSOCKS5(t *testing.T) {
	// Given a dialer that reaches a silent backhaul through a SOCKS5 proxy
	proxyURL := silentSOCKS5(t)
	dialer := websocket.Dialer{
		Proxy:            http.ProxyURL(proxyURL),
		NetDialContext:   BoundWebsocketDial(nil),
		HandshakeTimeout: 200 * time.Millisecond,
	}

	// When it dials
	done := make(chan error, 1)
	go func() {
		conn, _, err := dialer.Dial("ws://backhaul.example/ws/", nil)
		if conn != nil {
			_ = conn.Close()
		}
		done <- err
	}()

	// Then the dial gives up once HandshakeTimeout has passed
	select {
	case err := <-done:
		var netErr net.Error
		require.ErrorAs(t, err, &netErr)
		assert.True(t, netErr.Timeout(), "want a timeout, got %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("the dial outlived HandshakeTimeout: the SOCKS5 dialer cleared the socket deadline")
	}
}

func TestBoundWebsocketDial_ConnectionOutlivesHandshakeTimeout(t *testing.T) {
	// Given an echo server and a dial bounded by a short HandshakeTimeout
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer func() { _ = c.Close() }()
		for {
			mt, msg, err := c.ReadMessage()
			if err != nil || c.WriteMessage(mt, msg) != nil {
				return
			}
		}
	}))
	t.Cleanup(srv.Close)
	dialer := websocket.Dialer{NetDialContext: BoundWebsocketDial(nil), HandshakeTimeout: 100 * time.Millisecond}
	conn, _, err := dialer.Dial("ws"+strings.TrimPrefix(srv.URL, "http"), nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	// When the connection is used after HandshakeTimeout has passed
	time.Sleep(300 * time.Millisecond)
	require.NoError(t, conn.WriteMessage(websocket.TextMessage, []byte("ping")))
	_, msg, err := conn.ReadMessage()

	// Then the connection still works
	require.NoError(t, err)
	assert.Equal(t, "ping", string(msg))
}
