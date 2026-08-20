package runner

import (
	"errors"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
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
	}

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
