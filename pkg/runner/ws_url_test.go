package runner

import (
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/alpacax/alpamon/v2/pkg/config"
	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestServerHostFromURL(t *testing.T) {
	tests := []struct {
		name   string
		rawURL string
		want   string
	}{
		{name: "strips the token bearing path", rawURL: "wss://alpacon.io/ws/tunnels/abc123secret/", want: "alpacon.io"},
		{name: "keeps the port", rawURL: "ws://127.0.0.1:8000/ws/tunnels/abc123secret/", want: "127.0.0.1:8000"},
		{name: "hostless URL", rawURL: "not-a-url", want: "invalid"},
		{name: "empty URL", rawURL: "", want: "invalid"},
		{name: "path-only URL reports the server host", rawURL: "/ws/tunnels/abc123secret/", want: "console.example.com:8443"},
	}

	setServerURL(t, "https://console.example.com:8443")
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, ServerHostFromURL(tc.rawURL))
		})
	}
}

func TestSanitizeURLError(t *testing.T) {
	t.Run("replaces the URL with its host", func(t *testing.T) {
		inner := errors.New("dial tcp: connection refused")
		err := sanitizeURLError(&url.Error{Op: "parse", URL: "wss://alpacon.io/ws/tunnels/abc123secret/", Err: inner})

		assert.NotContains(t, err.Error(), "abc123secret")
		assert.Contains(t, err.Error(), "alpacon.io")
		assert.ErrorIs(t, err, inner)
	})

	t.Run("passes other errors through", func(t *testing.T) {
		inner := errors.New("websocket: bad handshake")
		assert.Equal(t, inner, sanitizeURLError(inner))
	})
}

// socketTargetCase is one URL Alpacon may send to open a socket, checked
// against a server configured at http://<host>.
type socketTargetCase struct {
	name     string
	target   string
	wantPath string // request URI the server sees when the target is accepted
	wantErr  string // refusal reason when the target is refused
}

// socketTargetCases builds the cases for host. The foreign host keeps host's
// port and names a different hostname, which a test server on 127.0.0.1 still
// answers, so a target that is not refused visibly reaches it.
func socketTargetCases(host string) []socketTargetCase {
	_, port, _ := net.SplitHostPort(host)
	foreign := net.JoinHostPort("localhost", port)
	return []socketTargetCase{
		{name: "path-only accepted", target: "/ws/channel/abc/", wantPath: "/ws/channel/abc/"},
		{name: "path-only with query accepted", target: "/ws/channel/abc/?token=t1", wantPath: "/ws/channel/abc/?token=t1"},
		{name: "same host accepted", target: "ws://" + host + "/ws/channel/abc/", wantPath: "/ws/channel/abc/"},
		{name: "foreign host refused", target: "ws://" + foreign + "/ws/channel/abc/", wantErr: "does not match server host"},
		{name: "scheme mismatch refused", target: "wss://" + host + "/ws/channel/abc/", wantErr: "does not match expected scheme"},
		{name: "scheme-relative refused", target: "//" + host + "/ws/channel/abc/", wantErr: "scheme-relative"},
		{name: "relative path refused", target: "ws/channel/abc/", wantErr: "must start with /"},
		{name: "empty refused", target: "", wantErr: "must start with /"},
		{name: "userinfo refused", target: "ws://user@" + host + "/ws/channel/abc/", wantErr: "userinfo"},
		{name: "backslash in path-only refused", target: "/ws\\channel/abc/", wantErr: "backslash"},
		{name: "backslash in absolute URL refused", target: "ws://" + host + "/ws\\channel/abc/", wantErr: "backslash"},
	}
}

// newSocketTargetServer starts a websocket peer and reports the request URI
// of every request it receives.
func newSocketTargetServer(t *testing.T) (*httptest.Server, <-chan string) {
	t.Helper()
	hits := make(chan string, 8)
	upgrader := websocket.Upgrader{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits <- r.URL.RequestURI()
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		go func() {
			defer func() { _ = conn.Close() }()
			for {
				if _, _, err := conn.ReadMessage(); err != nil {
					return
				}
			}
		}()
	}))
	t.Cleanup(srv.Close)
	return srv, hits
}

func setServerURL(t *testing.T, serverURL string) {
	t.Helper()
	prev := config.GlobalSettings.ServerURL
	t.Cleanup(func() { config.GlobalSettings.ServerURL = prev })
	config.GlobalSettings.ServerURL = serverURL
}

func assertSocketTarget(t *testing.T, tc socketTargetCase, err error, hits <-chan string) {
	t.Helper()
	if tc.wantErr != "" {
		require.ErrorContains(t, err, tc.wantErr)
		assert.Empty(t, hits, "a refused target must not reach the network")
		return
	}
	require.NoError(t, err)
	select {
	case got := <-hits:
		assert.Equal(t, tc.wantPath, got)
	case <-time.After(5 * time.Second):
		t.Fatal("the server never saw the request")
	}
}

func TestValidateWebSocketURL_Targets(t *testing.T) {
	const host = "console.example.com:8000"
	setServerURL(t, "http://"+host)

	for _, tc := range socketTargetCases(host) {
		t.Run(tc.name, func(t *testing.T) {
			got, err := validateWebSocketURL(tc.target)
			if tc.wantErr != "" {
				require.ErrorContains(t, err, tc.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, "ws://"+host+tc.wantPath, got)
		})
	}
}

func TestValidateWebSocketURL_PathOnlyUsesSecureScheme(t *testing.T) {
	setServerURL(t, "https://console.example.com")

	got, err := validateWebSocketURL("/ws/channel/abc/?token=t1")
	require.NoError(t, err)
	assert.Equal(t, "wss://console.example.com/ws/channel/abc/?token=t1", got)
}

func TestFtpConnect_Targets(t *testing.T) {
	srv, hits := newSocketTargetServer(t)
	host := strings.TrimPrefix(srv.URL, "http://")
	// The ftp worker runs without the agent's configuration and checks
	// against the server URL it is started with.
	setServerURL(t, "")

	for _, tc := range socketTargetCases(host) {
		t.Run(tc.name, func(t *testing.T) {
			fc := &FtpClient{url: tc.target, serverURL: srv.URL, requestHeader: http.Header{}}
			err := fc.connect()
			if fc.conn != nil {
				t.Cleanup(func() { _ = fc.conn.Close() })
			}
			assertSocketTarget(t, tc, err, hits)
		})
	}
}

func TestTunnelConnect_Targets(t *testing.T) {
	srv, hits := newSocketTargetServer(t)
	host := strings.TrimPrefix(srv.URL, "http://")
	setServerURL(t, srv.URL)

	for _, tc := range socketTargetCases(host) {
		t.Run(tc.name, func(t *testing.T) {
			client := NewTunnelClient("target-test", ClientTypeCLI, 22, "", "", tc.target)
			err := client.connect()
			t.Cleanup(func() {
				if client.session != nil {
					_ = client.session.Close()
				}
				if client.wsConn != nil {
					_ = client.wsConn.Close()
				}
				client.cancel()
			})
			assertSocketTarget(t, tc, err, hits)
		})
	}
}
