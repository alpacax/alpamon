package scheduler

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

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
		{name: "redirect to another port drops the key", target: "/to-other-port", want: uploadHit{server: "other", path: "/final"}},
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
