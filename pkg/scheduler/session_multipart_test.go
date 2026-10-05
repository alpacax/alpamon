package scheduler

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/alpacax/alpamon/v2/pkg/config"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type uploadHit struct {
	server string
	path   string
	auth   string
}

func TestMultipartRequest_CarriesTheKeyOnlyToTheServer(t *testing.T) {
	hits := make(chan uploadHit, 8)

	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits <- uploadHit{server: "other", path: r.URL.Path, auth: r.Header.Get("Authorization")}
	}))
	t.Cleanup(other.Close)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/to-other-port" {
			http.Redirect(w, r, other.URL+"/final", http.StatusFound)
			return
		}
		hits <- uploadHit{server: "server", path: r.URL.Path, auth: r.Header.Get("Authorization")}
	}))
	t.Cleanup(srv.Close)

	host := strings.TrimPrefix(srv.URL, "http://")
	_, port, err := net.SplitHostPort(host)
	require.NoError(t, err)
	// localhost reaches the same test server under a different host.
	foreign := "http://" + net.JoinHostPort("localhost", port)

	const agentAuth = `id="agent-id", key="agent-key"`
	session := &Session{BaseURL: srv.URL, Client: &http.Client{}, Authorization: agentAuth}

	tests := []struct {
		name    string
		target  string
		want    uploadHit
		wantErr string
	}{
		{name: "path-only resolves to the server and carries the key", target: "/api/uploads/1/", want: uploadHit{server: "server", path: "/api/uploads/1/", auth: agentAuth}},
		{name: "same server carries the key", target: srv.URL + "/api/uploads/1/", want: uploadHit{server: "server", path: "/api/uploads/1/", auth: agentAuth}},
		{name: "foreign host uploads without the key", target: foreign + "/bucket/object", want: uploadHit{server: "server", path: "/bucket/object"}},
		{name: "another port uploads without the key", target: other.URL + "/bucket/object", want: uploadHit{server: "other", path: "/bucket/object"}},
		{name: "redirect to another port drops the key", target: srv.URL + "/to-other-port", want: uploadHit{server: "other", path: "/final"}},
		{name: "scheme-relative refused", target: "//" + host + "/api/uploads/1/", wantErr: "scheme-relative"},
		{name: "userinfo refused", target: "http://user:pass@" + host + "/api/uploads/1/", wantErr: "userinfo"},
		{name: "backslash refused", target: "/api\\uploads/1/", wantErr: "backslash"},
		{name: "relative path refused", target: "api/uploads/1/", wantErr: "must start with /"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := session.MultipartRequest(tc.target, strings.NewReader("x"), "text/plain", 1, 5)
			if tc.wantErr != "" {
				require.ErrorContains(t, err, tc.wantErr)
				assert.Empty(t, hits, "a refused URL must not reach the network")
				return
			}
			require.NoError(t, err)
			require.Len(t, hits, 1)
			assert.Equal(t, tc.want, <-hits)
		})
	}
}

func TestMultipartRequest_KeepsTheClientRedirectPolicy(t *testing.T) {
	var redirected bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/start" {
			http.Redirect(w, r, "/next", http.StatusFound)
			return
		}
		redirected = true
	}))
	t.Cleanup(srv.Close)

	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	session := &Session{BaseURL: srv.URL, Client: client, Authorization: "key"}

	_, code, err := session.MultipartRequest("/start", strings.NewReader("x"), "text/plain", 1, 5)
	require.NoError(t, err)
	assert.Equal(t, http.StatusFound, code)
	assert.False(t, redirected)
}

// A streamed body, which is what file upload sends, cannot be replayed, so
// Go does not follow a 307 or 308 and neither the body nor the key moves on.
func TestMultipartRequest_DoesNotFollowA307WithAStreamedBody(t *testing.T) {
	var otherHit bool
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		otherHit = true
	}))
	t.Cleanup(other.Close)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+"/final", http.StatusTemporaryRedirect)
	}))
	t.Cleanup(srv.Close)

	session := &Session{BaseURL: srv.URL, Client: &http.Client{}, Authorization: "key"}

	pr, pw := io.Pipe()
	go func() {
		_, _ = io.WriteString(pw, "file content")
		_ = pw.Close()
	}()

	_, code, err := session.MultipartRequest("/api/uploads/1/", pr, "text/plain", -1, 5)
	require.NoError(t, err)
	assert.Equal(t, http.StatusTemporaryRedirect, code)
	assert.False(t, otherHit, "the upload must not reach the redirect target")
}

func TestMultipartRequest_ErrorNamesOnlyTheHost(t *testing.T) {
	closed := httptest.NewServer(http.NotFoundHandler())
	closedURL := closed.URL
	closed.Close()

	session := &Session{BaseURL: closedURL, Client: &http.Client{}, Authorization: "key"}
	_, _, err := session.MultipartRequest(closedURL+"/api/uploads/secret-path/?sig=secret-sig", strings.NewReader("x"), "text/plain", 1, 5)
	require.Error(t, err)
	assert.Contains(t, err.Error(), strings.TrimPrefix(closedURL, "http://"))
	assert.NotContains(t, err.Error(), "secret")
}

func TestInitSession_RedirectCarriesTheKeyOnlyOnTheServer(t *testing.T) {
	type hit struct{ server, auth string }
	hits := make(chan hit, 4)

	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits <- hit{server: "other", auth: r.Header.Get("Authorization")}
	}))
	t.Cleanup(other.Close)

	var srvURL string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/to-server":
			http.Redirect(w, r, srvURL+"/final", http.StatusFound)
		case "/to-other-port":
			http.Redirect(w, r, other.URL+"/final", http.StatusFound)
		default:
			hits <- hit{server: "server", auth: r.Header.Get("Authorization")}
		}
	}))
	t.Cleanup(srv.Close)
	srvURL = srv.URL

	prev := config.GlobalSettings
	t.Cleanup(func() { config.GlobalSettings = prev })
	config.GlobalSettings = config.Settings{ServerURL: srv.URL, ID: "agent-id", Key: "agent-key", SSLVerify: true}
	const agentAuth = `id="agent-id", key="agent-key"`

	session := InitSession()

	_, _, err := session.Get("/to-server", 5)
	require.NoError(t, err)
	require.Len(t, hits, 1)
	assert.Equal(t, hit{server: "server", auth: agentAuth}, <-hits)

	_, _, err = session.Get("/to-other-port", 5)
	require.NoError(t, err)
	require.Len(t, hits, 1)
	assert.Equal(t, hit{server: "other"}, <-hits)
}
