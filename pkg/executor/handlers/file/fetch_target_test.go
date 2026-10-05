package file

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/alpacax/alpamon/v2/pkg/config"
	"github.com/alpacax/alpamon/v2/pkg/executor/handlers/common"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fetchHit struct {
	uri  string
	auth string
}

func TestFetchFromURL_Targets(t *testing.T) {
	hits := make(chan fetchHit, 8)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits <- fetchHit{uri: r.URL.RequestURI(), auth: r.Header.Get("Authorization")}
		_, _ = io.WriteString(w, "content")
	}))
	t.Cleanup(srv.Close)

	host := strings.TrimPrefix(srv.URL, "http://")
	_, port, err := net.SplitHostPort(host)
	require.NoError(t, err)
	// localhost reaches the same test server under a different host.
	foreign := net.JoinHostPort("localhost", port)

	prev := config.GlobalSettings
	t.Cleanup(func() { config.GlobalSettings = prev })
	config.GlobalSettings.ServerURL = srv.URL
	config.GlobalSettings.ID = "agent-id"
	config.GlobalSettings.Key = "agent-key"
	const agentAuth = `id="agent-id", key="agent-key"`

	tests := []struct {
		name     string
		target   string
		wantURI  string
		wantAuth string
		wantErr  string
	}{
		{name: "path-only resolves to the server and carries the key", target: "/api/files/1/download/?t=1", wantURI: "/api/files/1/download/?t=1", wantAuth: agentAuth},
		{name: "same host carries the key", target: srv.URL + "/api/files/1/download/", wantURI: "/api/files/1/download/", wantAuth: agentAuth},
		{name: "foreign host is fetched without the key", target: "http://" + foreign + "/bucket/object?sig=1", wantURI: "/bucket/object?sig=1"},
		{name: "scheme-relative refused", target: "//" + host + "/api/files/1/download/", wantErr: "scheme-relative"},
		{name: "relative path refused", target: "api/files/1/download/", wantErr: "must start with /"},
		{name: "userinfo refused", target: "http://user:pass@" + host + "/api/files/1/download/", wantErr: "userinfo"},
		{name: "backslash refused", target: "/api\\files/1/download/", wantErr: "backslash"},
	}

	h := NewFileHandler(common.NewMockCommandExecutor(t), nil)
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rc, err := h.fetchFromURL(context.Background(), tc.target)
			if tc.wantErr != "" {
				if err == nil {
					_ = rc.Close()
				}
				require.ErrorContains(t, err, tc.wantErr)
				assert.Empty(t, hits, "a refused URL must not reach the network")
				return
			}
			require.NoError(t, err)
			body, err := io.ReadAll(rc)
			_ = rc.Close()
			require.NoError(t, err)
			assert.Equal(t, "content", string(body))

			require.Len(t, hits, 1)
			hit := <-hits
			assert.Equal(t, tc.wantURI, hit.uri)
			assert.Equal(t, tc.wantAuth, hit.auth)
		})
	}
}

func TestFetchFromURL_FailuresNameOnlyTheHost(t *testing.T) {
	var logged bytes.Buffer
	prevLogger := log.Logger
	t.Cleanup(func() { log.Logger = prevLogger })
	log.Logger = zerolog.New(&logged)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)

	prev := config.GlobalSettings
	t.Cleanup(func() { config.GlobalSettings = prev })
	config.GlobalSettings.ServerURL = srv.URL

	h := NewFileHandler(common.NewMockCommandExecutor(t), nil)

	t.Run("non-2xx response", func(t *testing.T) {
		_, err := h.fetchFromURL(context.Background(), srv.URL+"/files/secret-path/?sig=secret-sig")
		require.Error(t, err)
		assert.Contains(t, logged.String(), strings.TrimPrefix(srv.URL, "http://"))
		assert.NotContains(t, logged.String(), "secret")
		assert.NotContains(t, err.Error(), "secret")
	})

	t.Run("transport error", func(t *testing.T) {
		closed := httptest.NewServer(http.NotFoundHandler())
		closedURL := closed.URL
		closed.Close()

		_, err := h.fetchFromURL(context.Background(), closedURL+"/files/secret-path/?sig=secret-sig")
		require.Error(t, err)
		assert.Contains(t, err.Error(), strings.TrimPrefix(closedURL, "http://"))
		assert.NotContains(t, err.Error(), "secret")
	})
}

func TestFetchFromURL_RedirectCarriesTheKeyOnlyOnTheServer(t *testing.T) {
	type hit struct{ server, auth string }
	hits := make(chan hit, 8)

	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits <- hit{server: "other", auth: r.Header.Get("Authorization")}
		_, _ = io.WriteString(w, "content")
	}))
	t.Cleanup(other.Close)

	var srvURL string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/to-server":
			http.Redirect(w, r, srvURL+"/final", http.StatusFound)
		case "/to-other-port":
			// Same hostname, different port: Go's own redirect policy keeps
			// the Authorization header here.
			http.Redirect(w, r, other.URL+"/final", http.StatusFound)
		default:
			hits <- hit{server: "server", auth: r.Header.Get("Authorization")}
			_, _ = io.WriteString(w, "content")
		}
	}))
	t.Cleanup(srv.Close)
	srvURL = srv.URL

	prev := config.GlobalSettings
	t.Cleanup(func() { config.GlobalSettings = prev })
	config.GlobalSettings.ServerURL = srv.URL
	config.GlobalSettings.ID = "agent-id"
	config.GlobalSettings.Key = "agent-key"
	const agentAuth = `id="agent-id", key="agent-key"`

	tests := []struct {
		name   string
		target string
		want   hit
	}{
		{name: "redirect within the server keeps the key", target: "/to-server", want: hit{server: "server", auth: agentAuth}},
		{name: "redirect to another port drops the key", target: "/to-other-port", want: hit{server: "other"}},
	}

	h := NewFileHandler(common.NewMockCommandExecutor(t), nil)
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rc, err := h.fetchFromURL(context.Background(), tc.target)
			require.NoError(t, err)
			_, _ = io.Copy(io.Discard, rc)
			_ = rc.Close()

			require.Len(t, hits, 1)
			assert.Equal(t, tc.want, <-hits)
		})
	}
}
