package wsclient

import (
	"bufio"
	"crypto/sha1"
	"encoding/base64"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDial_HandsOverAWorkingConnection(t *testing.T) {
	srv := newBackhaulServer(t)
	cfg := testConfig(srv.url)

	conn, resp, err := Dial(t.Context(), cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	assert.Equal(t, http.StatusSwitchingProtocols, resp.StatusCode)
	sc := recv(t, srv.accepted, "the connection")
	assert.Equal(t, `id="srv-1", key="secret"`, sc.header.Get("Authorization"))

	require.NoError(t, conn.WriteMessage(websocket.TextMessage, []byte("hello")))
	assert.Equal(t, "hello", string(recv(t, sc.received, "the frame")))

	sc.push(t, websocket.TextMessage, "back")
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(waitFor)))
	_, payload, err := conn.ReadMessage()
	require.NoError(t, err)
	assert.Equal(t, "back", string(payload))
}

func TestDial_AppliesTheReadLimit(t *testing.T) {
	srv := newBackhaulServer(t)
	cfg := testConfig(srv.url)
	cfg.ReadLimit = 16

	conn, _, err := Dial(t.Context(), cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	recv(t, srv.accepted, "the connection").push(t, websocket.TextMessage, strings.Repeat("x", 64))
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(waitFor)))
	_, _, err = conn.ReadMessage()
	assert.ErrorIs(t, err, websocket.ErrReadLimit)
}

func TestDial_RejectsABadConfigBeforeDialing(t *testing.T) {
	var hits atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
	t.Cleanup(ts.Close)

	cfg := testConfig(strings.Replace(ts.URL, "http", "ftp", 1))
	_, _, err := Dial(t.Context(), cfg)
	assert.ErrorContains(t, err, `scheme "ftp"`)

	cfg = testConfig(ts.URL)
	cfg.Key = ""
	_, _, err = Dial(t.Context(), cfg)
	assert.ErrorContains(t, err, "Key is required")

	assert.Zero(t, hits.Load(), "a config error must not reach the network")
}

func TestDial_IgnoresTheLoopOnlyFields(t *testing.T) {
	srv := newBackhaulServer(t)
	cfg := testConfig(srv.url)
	cfg.MinBackoff = -time.Second // invalid for a Client, irrelevant to one dial

	conn, _, err := Dial(t.Context(), cfg)
	require.NoError(t, err)
	_ = conn.Close()
}

func TestDial_ReportsARejectedHandshake(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
	}))
	t.Cleanup(ts.Close)

	conn, resp, err := Dial(t.Context(), testConfig(ts.URL))

	assert.Nil(t, conn)
	require.ErrorIs(t, err, websocket.ErrBadHandshake)
	assert.ErrorContains(t, err, "HTTP 401")
	require.NotNil(t, resp, "the response comes back with the error so the caller can inspect it")
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

// TestDial_RefusesAnExtensionItNeverOffered covers a server that answers with
// permessage-deflate the client never asked for. gorilla/websocket switches
// decompression on for it regardless, and a read limit counts compressed
// bytes, so accepting would let a small frame inflate without bound.
func TestDial_RefusesAnExtensionItNeverOffered(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, buf, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		sum := sha1.Sum([]byte(r.Header.Get("Sec-WebSocket-Key") + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
		_, _ = buf.WriteString("HTTP/1.1 101 Switching Protocols\r\n" +
			"Upgrade: websocket\r\nConnection: Upgrade\r\n" +
			"Sec-WebSocket-Accept: " + base64.StdEncoding.EncodeToString(sum[:]) + "\r\n" +
			"Sec-WebSocket-Extensions: permessage-deflate; server_no_context_takeover; client_no_context_takeover\r\n\r\n")
		_ = buf.Flush()
	}))
	t.Cleanup(ts.Close)

	conn, _, err := Dial(t.Context(), testConfig(ts.URL))

	assert.Nil(t, conn)
	assert.ErrorContains(t, err, "permessage-deflate")
	assert.ErrorContains(t, err, "did not offer")
}

// TestDial_SurvivesAProxyWithoutAReasonPhrase covers gorilla/websocket
// v1.5.3 reading the reason phrase out of a CONNECT status line that has
// none, which panics the dialing goroutine. For an agent that goroutine is
// the process, and a proxy is reachable by default through the environment,
// so this has to come back as an error.
func TestDial_SurvivesAProxyWithoutAReasonPhrase(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			reader := bufio.NewReader(conn)
			for { // drain the CONNECT request
				line, err := reader.ReadString('\n')
				if err != nil || line == "\r\n" {
					break
				}
			}
			_, _ = conn.Write([]byte("HTTP/1.1 407\r\n\r\n")) // a status line with no reason phrase
			_ = conn.Close()
		}
	}()

	proxyURL, err := url.Parse("http://" + listener.Addr().String())
	require.NoError(t, err)
	cfg := testConfig("wss://backhaul.example.com/ws/")
	cfg.Dialer = DefaultDialer()
	cfg.Dialer.Proxy = func(*http.Request) (*url.URL, error) { return proxyURL, nil }

	conn, _, err := Dial(t.Context(), cfg)

	assert.Nil(t, conn)
	require.Error(t, err, "a malformed proxy response must not take the process down")
	assert.ErrorContains(t, err, "proxy")
}
