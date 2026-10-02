package utils

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/alpacax/alpamon/v2/pkg/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func get(t *testing.T, client *http.Client, url string) {
	t.Helper()
	resp, err := client.Get(url)
	require.NoError(t, err)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "ok", string(body))
}

func setSettings(t *testing.T, s config.Settings) {
	t.Helper()
	saved := config.GlobalSettings
	t.Cleanup(func() { config.GlobalSettings = saved })
	config.GlobalSettings = s
}

func TestNewHTTPClient_GivenTwoClients_WhenRequestingSequentially_ThenOneConnectionIsReused(t *testing.T) {
	var newConns int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			atomic.AddInt32(&newConns, 1)
		}
	}
	server.StartTLS()
	t.Cleanup(server.Close)
	setSettings(t, config.Settings{SSLVerify: false})

	first, second := NewHTTPClient(), NewHTTPClient()
	get(t, first, server.URL)
	get(t, second, server.URL)

	assert.NotSame(t, first, second, "each call returns its own client so callers can set Timeout")
	assert.Equal(t, int32(1), atomic.LoadInt32(&newConns))
}

func TestNewHTTPClient_GivenSettingsChange_WhenCalledAgain_ThenTransportIsRebuilt(t *testing.T) {
	setSettings(t, config.Settings{SSLVerify: false})
	before := NewHTTPClient().Transport
	require.Same(t, before, NewHTTPClient().Transport)

	config.GlobalSettings = config.Settings{SSLVerify: true}
	after := NewHTTPClient().Transport

	assert.NotSame(t, before, after)
}

func TestNewHTTPClient_GivenUnreadableCACert_WhenCalledAgain_ThenTransportIsRebuilt(t *testing.T) {
	setSettings(t, config.Settings{SSLVerify: true, CaCert: filepath.Join(t.TempDir(), "missing.pem")})
	before := NewHTTPClient().Transport

	after := NewHTTPClient().Transport

	assert.NotSame(t, before, after, "a failed CA read must be retried on the next call")
}

func BenchmarkNewHTTPClient(b *testing.B) {
	saved := config.GlobalSettings
	b.Cleanup(func() { config.GlobalSettings = saved })
	config.GlobalSettings = config.Settings{SSLVerify: true}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = NewHTTPClient()
	}
}
