//go:build !windows

package runner

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/alpacax/alpamon/v2/pkg/logger"
	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFtpInheritedProxyConnection(t *testing.T) {
	if endpoint := os.Getenv("ALPAMON_TEST_FTP_ENDPOINT"); endpoint != "" {
		client := NewFtpClient(FtpConfigData{URL: "/ftp", ServerURL: endpoint, Logger: logger.NewFtpLogger(), Connection: FtpConnectionConfig{ProxySocket: true}})
		require.NotNil(t, client)
		require.NoError(t, client.connect())
		require.NoError(t, client.conn.Close())
		return
	}
	upgrader := websocket.Upgrader{}
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err == nil {
			_ = conn.Close()
		}
	}))
	defer peer.Close()
	endpoint, err := url.Parse(peer.URL)
	require.NoError(t, err)
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect || r.Host != endpoint.Host || r.Header.Get("Proxy-Authorization") != "Basic dXNlcjpwYXNz" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		remote, err := net.DialTimeout("tcp", endpoint.Host, time.Second)
		if err != nil {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		defer func() { _ = remote.Close() }()
		client, buf, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer func() { _ = client.Close() }()
		_, _ = buf.WriteString("HTTP/1.1 200 OK\r\n\r\n")
		_ = buf.Flush()
		go func() { _, _ = io.Copy(remote, client) }()
		_, _ = io.Copy(client, remote)
	}))
	defer proxy.Close()
	proxyURL, err := url.Parse(proxy.URL)
	require.NoError(t, err)
	proxyURL.User = url.UserPassword("user", "pass")
	socket, err := OpenFtpProxySocket(t.Context(), "/ftp", peer.URL, proxyURL.String())
	require.NoError(t, err)
	defer func() { _ = socket.Close() }()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestFtpInheritedProxyConnection$")
	cmd.Env = []string{"ALPAMON_TEST_FTP_ENDPOINT=" + peer.URL}
	cmd.ExtraFiles = []*os.File{socket}
	output, err := cmd.CombinedOutput()
	assert.NoError(t, err, "%s", output)
}
