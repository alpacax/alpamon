package migrate

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBestEffortUnregister_RedirectDropsTheKeyOffTheTarget(t *testing.T) {
	auth := make(chan string, 1)
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth <- r.Header.Get("Authorization")
	}))
	t.Cleanup(other.Close)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	t.Cleanup(srv.Close)

	BestEffortUnregister(srv.URL, "agent-id", "agent-key", true, "")

	assert.Len(t, auth, 1)
	assert.Empty(t, <-auth)
}
