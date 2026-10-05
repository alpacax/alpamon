package migrate

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/alpacax/alpamon/v2/pkg/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFetchCurrentName_RedirectDropsTheKeyOffTheServer(t *testing.T) {
	auth := make(chan string, 1)
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth <- r.Header.Get("Authorization")
		_, _ = w.Write([]byte(`{"name":"box"}`))
	}))
	t.Cleanup(other.Close)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+r.URL.Path, http.StatusFound)
	}))
	t.Cleanup(srv.Close)

	_, err := fetchCurrentName(context.Background(), &config.ServerConfig{URL: srv.URL, ID: "agent-id", Key: "agent-key"})
	require.NoError(t, err)
	require.Len(t, auth, 1)
	assert.Empty(t, <-auth)
}
