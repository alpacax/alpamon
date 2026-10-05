package runner

import (
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alpacax/alpamon/v2/pkg/config"
	"github.com/alpacax/alpamon/v2/pkg/logger"
	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newFtpTLSServer starts a TLS WebSocket peer whose certificate no system
// root trusts.
func newFtpTLSServer(t *testing.T) *httptest.Server {
	t.Helper()
	upgrader := websocket.Upgrader{}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		_ = conn.Close()
	}))
	t.Cleanup(srv.Close)
	return srv
}

// newTLSFtpClient builds the client the ftp worker builds. The worker does not
// load the agent's configuration, so GlobalSettings stays at its zero value.
func newTLSFtpClient(t *testing.T, srv *httptest.Server, data FtpConfigData) *FtpClient {
	t.Helper()
	prev := config.GlobalSettings
	t.Cleanup(func() { config.GlobalSettings = prev })
	config.GlobalSettings = config.Settings{}

	data.URL = "wss" + strings.TrimPrefix(srv.URL, "https") + "/ws/ftp/"
	data.ServerURL = srv.URL
	data.HomeDirectory = t.TempDir()
	data.Logger = logger.NewFtpLogger()
	fc := NewFtpClient(data)
	require.NotNil(t, fc)
	return fc
}

// dialFtp dials the way RunFtpBackground does, without its os.Exit teardown.
func dialFtp(fc *FtpClient) error {
	dialer := websocket.Dialer{TLSClientConfig: fc.tlsConfig}
	conn, _, err := dialer.Dial(fc.url, fc.requestHeader)
	if conn != nil {
		_ = conn.Close()
	}
	return err
}

func serverCAPEM(srv *httptest.Server) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
}

func TestFtpDialer_VerifiesTheServerByDefault(t *testing.T) {
	srv := newFtpTLSServer(t)
	fc := newTLSFtpClient(t, srv, FtpConfigData{})

	require.NotNil(t, fc.tlsConfig)
	assert.False(t, fc.tlsConfig.InsecureSkipVerify)
	assert.ErrorContains(t, dialFtp(fc), "certificate")
}

func TestFtpDialer_SkipsVerificationWhenConfiguredOff(t *testing.T) {
	srv := newFtpTLSServer(t)
	fc := newTLSFtpClient(t, srv, FtpConfigData{SkipSSLVerify: true})

	require.NotNil(t, fc.tlsConfig)
	assert.True(t, fc.tlsConfig.InsecureSkipVerify)
	assert.NoError(t, dialFtp(fc))
}

func TestFtpDialer_TrustsTheConfiguredCA(t *testing.T) {
	srv := newFtpTLSServer(t)
	fc := newTLSFtpClient(t, srv, FtpConfigData{CaCertPEM: serverCAPEM(srv)})

	require.NotNil(t, fc.tlsConfig)
	assert.False(t, fc.tlsConfig.InsecureSkipVerify)
	assert.NotNil(t, fc.tlsConfig.RootCAs)
	assert.NoError(t, dialFtp(fc))
}

func TestNewFtpClient_RefusesACAWithNoCertificate(t *testing.T) {
	fc := NewFtpClient(FtpConfigData{
		URL:           "wss://console.example.com/ws/ftp/",
		ServerURL:     "https://console.example.com",
		HomeDirectory: t.TempDir(),
		Logger:        logger.NewFtpLogger(),
		CaCertPEM:     []byte("not a certificate"),
	})
	assert.Nil(t, fc)
}

func TestFtpWorkerEnv(t *testing.T) {
	t.Run("no CA configured", func(t *testing.T) {
		env, err := FtpWorkerEnv("")
		require.NoError(t, err)
		assert.Empty(t, env)
	})

	t.Run("configured CA is passed by content", func(t *testing.T) {
		data := []byte("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n")
		path := filepath.Join(t.TempDir(), "ca.pem")
		require.NoError(t, os.WriteFile(path, data, 0o600))

		env, err := FtpWorkerEnv(path)
		require.NoError(t, err)
		assert.Equal(t, []string{FtpCaCertEnv + "=" + string(data)}, env)
	})

	t.Run("unreadable CA", func(t *testing.T) {
		_, err := FtpWorkerEnv(filepath.Join(t.TempDir(), "missing.pem"))
		assert.ErrorContains(t, err, "CA certificate")
	})
}
