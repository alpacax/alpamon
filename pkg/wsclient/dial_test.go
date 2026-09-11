package wsclient

import (
	"bufio"
	"context"
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"fmt"
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
	// gorilla/websocket reads every Sec-WebSocket-Extensions header it is
	// sent, so a server can hide the real one behind an empty first value.
	// Checking only the first value let that straight through, and the
	// connection came back with decompression on and a read limit that
	// counts compressed bytes: a small frame could then allocate without
	// bound.
	for name, extensions := range map[string][]string{
		"one header":                          {"permessage-deflate; server_no_context_takeover; client_no_context_takeover"},
		"hidden behind an empty first header": {"", "permessage-deflate; server_no_context_takeover; client_no_context_takeover"},
	} {
		t.Run(name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				conn, buf, err := w.(http.Hijacker).Hijack()
				if err != nil {
					return
				}
				defer func() { _ = conn.Close() }()
				sum := sha1.Sum([]byte(r.Header.Get("Sec-WebSocket-Key") + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
				response := "HTTP/1.1 101 Switching Protocols\r\n" +
					"Upgrade: websocket\r\nConnection: Upgrade\r\n" +
					"Sec-WebSocket-Accept: " + base64.StdEncoding.EncodeToString(sum[:]) + "\r\n"
				for _, ext := range extensions {
					response += "Sec-WebSocket-Extensions: " + ext + "\r\n"
				}
				_, _ = buf.WriteString(response + "\r\n")
				_ = buf.Flush()
			}))
			t.Cleanup(ts.Close)

			conn, _, err := Dial(t.Context(), testConfig(ts.URL))

			assert.Nil(t, conn, "a connection with decompression the client never asked for must be refused")
			assert.ErrorContains(t, err, "did not offer")
		})
	}
}

func TestUnofferedExtension(t *testing.T) {
	const deflate = "permessage-deflate; server_no_context_takeover; client_no_context_takeover"
	for _, tc := range []struct {
		name        string
		values      []string
		compression bool
		want        string
	}{
		{name: "no header"},
		{name: "an empty header", values: []string{""}},
		{name: "deflate, not offered", values: []string{deflate}, want: "permessage-deflate"},
		{name: "deflate, offered", values: []string{deflate}, compression: true},
		{name: "deflate in another case, offered", values: []string{"PerMessage-Deflate"}, compression: true},
		{name: "an unknown extension, with compression on", values: []string{"x-evil"}, compression: true, want: "x-evil"},
		{name: "an unknown one after deflate", values: []string{deflate + ", x-evil"}, compression: true, want: "x-evil"},
		{name: "deflate hidden behind an empty header", values: []string{"", deflate}, want: "permessage-deflate"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, found := unofferedExtension(tc.values, tc.compression)
			assert.Equal(t, tc.want != "", found)
			assert.Equal(t, tc.want, got)
		})
	}
}

// TestDial_KeepsTheCredentialOutOfTheResponse covers the request that
// http.ReadResponse hangs off the response it returns. Dial invites callers
// to inspect that response, and the request carries the Authorization
// header, so one logged struct would put the agent's key in the logs.
func TestDial_KeepsTheCredentialOutOfTheResponse(t *testing.T) {
	srv := newBackhaulServer(t)
	conn, resp, err := Dial(t.Context(), testConfig(srv.url))
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	require.NotNil(t, resp.Request)
	assert.Empty(t, resp.Request.Header.Get("Authorization"))
	assert.NotContains(t, fmt.Sprint(resp.Request.Header), "secret")
}

func TestDial_KeepsTheCredentialOutOfARejectedResponse(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "nope", http.StatusUnauthorized)
	}))
	t.Cleanup(ts.Close)

	_, resp, err := Dial(t.Context(), testConfig(ts.URL))

	require.Error(t, err)
	require.NotNil(t, resp)
	require.NotNil(t, resp.Request)
	assert.Empty(t, resp.Request.Header.Get("Authorization"))
}

// TestDial_HandsTheProxyAnHTTPScheme covers what DefaultDialer's
// http.ProxyFromEnvironment has to be given. That resolver matches
// HTTP_PROXY and HTTPS_PROXY on the request's scheme and answers nil for
// anything else, so a ws or wss scheme reaching it would turn every
// environment proxy off in silence, which is the sort of thing found in
// production rather than in a test. What keeps it from happening belongs to
// gorilla, not to this package: it rewrites the scheme before building the
// request it hands to Dialer.Proxy. Pin it, because nothing here would
// notice it changing.
func TestDial_HandsTheProxyAnHTTPScheme(t *testing.T) {
	for _, tc := range []struct{ url, want string }{
		{"ws://backhaul.example.com/ws/", "http"},
		{"wss://backhaul.example.com/ws/", "https"},
	} {
		t.Run(tc.want, func(t *testing.T) {
			var seen string
			cfg := testConfig(tc.url)
			cfg.Dialer = DefaultDialer()
			cfg.Dialer.Proxy = func(r *http.Request) (*url.URL, error) {
				seen = r.URL.Scheme
				return nil, nil
			}
			// gorilla consults Proxy before it dials, so the socket is never
			// needed and the name never has to resolve.
			cfg.Dialer.NetDialContext = func(context.Context, string, string) (net.Conn, error) {
				return nil, errors.New("the scheme the proxy saw is the whole test")
			}

			_, _, err := Dial(t.Context(), cfg)

			require.Error(t, err)
			assert.Equal(t, tc.want, seen, "http.ProxyFromEnvironment matches on this and nothing else")
		})
	}
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
	var tracker closeTrackingDialer
	cfg := testConfig("wss://backhaul.example.com/ws/")
	cfg.Dialer = tracker.dialer()
	cfg.Dialer.Proxy = func(*http.Request) (*url.URL, error) { return proxyURL, nil }

	conn, _, err := Dial(t.Context(), cfg)

	assert.Nil(t, conn)
	require.Error(t, err, "a malformed proxy response must not take the process down")
	assert.ErrorContains(t, err, "proxy")
	// The panic unwinds past gorilla's own cleanup, and finish only clears
	// deadlines, so the socket is closed here only because proxy.go closes it
	// on the line before the one that panics. Nothing in this package would
	// notice if that stopped being true, and a Run that keeps retrying would
	// leak an fd per attempt.
	assert.True(t, tracker.allClosed(),
		"the socket the proxy dial opened must be closed before the panic is turned into an error")
}
