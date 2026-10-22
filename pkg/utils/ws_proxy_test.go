package utils

import (
	"bytes"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"

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
