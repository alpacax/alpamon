package utils

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

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
	t.Cleanup(func() {
		config.GlobalSettings = saved
		resetSharedTransport()
	})
	config.GlobalSettings = s
	resetSharedTransport()
}

func resetSharedTransport() {
	transportMu.Lock()
	defer transportMu.Unlock()
	sharedTransport = nil
}

// serveOnceThenDrop answers the first request on each connection and closes the
// connection on the next one unanswered, as a server dropping an idle connection would.
func serveOnceThenDrop(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				r := bufio.NewReader(conn)
				req, err := http.ReadRequest(r)
				if err != nil {
					return
				}
				_, _ = io.Copy(io.Discard, req.Body)
				_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"))
				if req, err = http.ReadRequest(r); err == nil {
					_, _ = io.Copy(io.Discard, req.Body)
				}
			}()
		}
	}()
	return "http://" + ln.Addr().String()
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

func TestNewHTTPClient_GivenUnreadableCACert_WhenCalledAgain_ThenTransportIsRebuilt(t *testing.T) {
	setSettings(t, config.Settings{SSLVerify: true, CaCert: filepath.Join(t.TempDir(), "missing.pem")})
	before := NewHTTPClient().Transport

	after := NewHTTPClient().Transport

	assert.NotSame(t, before, after)
}

func TestNewHTTPClient_GivenCACertWithoutPEM_WhenCalledAgain_ThenTransportIsRebuilt(t *testing.T) {
	caCert := filepath.Join(t.TempDir(), "ca.pem")
	require.NoError(t, os.WriteFile(caCert, []byte("not a certificate"), 0o600))
	setSettings(t, config.Settings{SSLVerify: true, CaCert: caCert})
	before := NewHTTPClient().Transport

	after := NewHTTPClient().Transport

	assert.NotSame(t, before, after)
}

func TestPut_GivenServerDropsIdleConnection_WhenUploadingTwice_ThenSecondUploadSucceeds(t *testing.T) {
	url := serveOnceThenDrop(t)
	setSettings(t, config.Settings{})
	upload := func() (int, error) {
		_, status, err := Put(url, io.NopCloser(strings.NewReader("data")), 4, 5*time.Second)
		return status, err
	}
	status, err := upload()
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, status)

	status, err = upload()

	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, status)
}

func TestPut_WhenUploading_ThenAsksServerToCloseConnection(t *testing.T) {
	var closeRequested atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		closeRequested.Store(r.Close)
		_, _ = w.Write([]byte("ok"))
	}))
	t.Cleanup(server.Close)
	setSettings(t, config.Settings{})

	_, status, err := Put(server.URL, io.NopCloser(strings.NewReader("data")), 4, 5*time.Second)

	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, status)
	assert.True(t, closeRequested.Load())
}
