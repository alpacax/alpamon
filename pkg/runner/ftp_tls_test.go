package runner

import (
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
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
	require.NotNil(t, fc.tlsConfig.RootCAs)
	assert.Len(t, fc.tlsConfig.RootCAs.Subjects(), 1)
	assert.NoError(t, dialFtp(fc))
}

func TestNewFtpClient_RefusesACAWithNoCertificate(t *testing.T) {
	fc := NewFtpClient(FtpConfigData{
		URL:           "wss://console.invalid/ws/ftp/",
		ServerURL:     "https://console.invalid",
		HomeDirectory: t.TempDir(),
		Logger:        logger.NewFtpLogger(),
		CaCertPEM:     []byte("not a certificate"),
	})
	assert.Nil(t, fc)
}

func TestReadFtpCACert(t *testing.T) {
	t.Run("no CA configured", func(t *testing.T) {
		data, err := ReadFtpCACert("")
		require.NoError(t, err)
		assert.Nil(t, data)
	})

	t.Run("configured CA is read by content", func(t *testing.T) {
		want := []byte("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n")
		path := filepath.Join(t.TempDir(), "ca.pem")
		require.NoError(t, os.WriteFile(path, want, 0o600))

		data, err := ReadFtpCACert(path)
		require.NoError(t, err)
		assert.Equal(t, want, data)
	})

	t.Run("unreadable CA", func(t *testing.T) {
		_, err := ReadFtpCACert(filepath.Join(t.TempDir(), "missing.pem"))
		assert.ErrorContains(t, err, "CA certificate")
	})

	t.Run("CA over the size cap", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "big.pem")
		require.NoError(t, os.WriteFile(path, make([]byte, MaxFtpCACertSize+1), 0o600))

		_, err := ReadFtpCACert(path)
		assert.ErrorContains(t, err, "larger than")
	})
}

func TestRunFtpBackground_ReturnsTheConnectError(t *testing.T) {
	srv := newFtpTLSServer(t)
	fc := newTLSFtpClient(t, srv, FtpConfigData{})

	err := fc.RunFtpBackground()
	require.ErrorContains(t, err, "certificate")
	assert.Contains(t, err.Error(), strings.TrimPrefix(srv.URL, "https://"))
	assert.NotContains(t, err.Error(), "/ws/ftp/")
}

func TestFtpDialerUsesConfiguredProxyWithoutEnvironment(t *testing.T) {
	for _, key := range []string{"HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "no_proxy"} {
		t.Setenv(key, "")
		require.NoError(t, os.Unsetenv(key))
		_, present := os.LookupEnv(key)
		require.False(t, present)
	}
	requests := make(chan string, 1)
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests <- r.Method + " " + r.Host + " " + r.Header.Get("Proxy-Authorization")
		http.Error(w, "proxy reached", http.StatusBadGateway)
	}))
	defer proxy.Close()
	fc := NewFtpClient(FtpConfigData{URL: "wss://console.invalid/ws/ftp/", ServerURL: "https://console.invalid", HomeDirectory: t.TempDir(), Logger: logger.NewFtpLogger(), Connection: FtpConnectionConfig{ProxyURL: strings.Replace(proxy.URL, "://", "://user:pass@", 1)}})
	require.NotNil(t, fc)
	require.Error(t, fc.connect())
	assert.Nil(t, fc.proxy, "the proxy, which carries credentials, must not outlive the dial")
	select {
	case got := <-requests:
		assert.Equal(t, "CONNECT console.invalid:443 Basic dXNlcjpwYXNz", got)
	default:
		t.Fatal("worker did not dial the configured proxy")
	}
}

func TestFtpWorkerProxyResolvesDialTarget(t *testing.T) {
	if os.Getenv("ALPAMON_TEST_FTP_PROXY_CHILD") == "1" {
		config.GlobalSettings.ServerURL = "https://console.example.test:8443"
		settings, err := PrepareFtpWorkerConfig(os.Getenv("ALPAMON_TEST_FTP_TARGET"), "")
		require.NoError(t, err)
		assert.Equal(t, os.Getenv("ALPAMON_TEST_FTP_PROXY_WANT"), settings.Connection.ProxyURL)
		return
	}
	for _, tc := range []struct{ name, target, noProxy, want string }{
		{"path", "/ws/ftp/", "", "http://proxy.invalid:3128"},
		{"absolute", "wss://console.example.test:8443/ws/ftp/", "", "http://proxy.invalid:3128"},
		{"bypass", "/ws/ftp/", "console.example.test:8443", ""},
		{"different target port", "wss://console.example.test:9443/ws/ftp/", "console.example.test:9443", "http://proxy.invalid:3128"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cmd := exec.Command(os.Args[0], "-test.run=^TestFtpWorkerProxyResolvesDialTarget$")
			cmd.Env = []string{"ALPAMON_TEST_FTP_PROXY_CHILD=1", "ALPAMON_TEST_FTP_TARGET=" + tc.target, "ALPAMON_TEST_FTP_PROXY_WANT=" + tc.want, "HTTPS_PROXY=http://proxy.invalid:3128", "NO_PROXY=" + tc.noProxy}
			output, err := cmd.CombinedOutput()
			require.NoError(t, err, "%s", output)
		})
	}
}

func TestFtpDialerPreviousAgentUsesEnvironment(t *testing.T) {
	// A fresh process avoids net/http's cached proxy environment.
	if os.Getenv("ALPAMON_TEST_FTP_LEGACY_CHILD") != "1" {
		cmd := exec.Command(os.Args[0], "-test.run=^TestFtpDialerPreviousAgentUsesEnvironment$")
		cmd.Env = []string{"ALPAMON_TEST_FTP_LEGACY_CHILD=1", "HTTPS_PROXY=https://proxy.invalid:3128"}
		output, err := cmd.CombinedOutput()
		require.NoError(t, err, "%s", output)
		return
	}
	fc := NewFtpClient(FtpConfigData{URL: "wss://console.invalid/ws/ftp/", HomeDirectory: t.TempDir(), Logger: logger.NewFtpLogger(), Connection: FtpConnectionConfig{UseEnvironment: true}})
	require.NotNil(t, fc)
	require.NotNil(t, fc.proxy)
	req, err := http.NewRequest(http.MethodGet, "https://console.invalid/ws/ftp/", nil)
	require.NoError(t, err)
	proxy, err := fc.proxy(req)
	require.NoError(t, err)
	assert.Nil(t, proxy, "unsupported proxy schemes must dial directly")
	assert.Nil(t, fc.tlsConfig.RootCAs)
}
