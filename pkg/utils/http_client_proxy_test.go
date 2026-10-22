package utils

import (
	"bufio"
	"crypto/tls"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/alpacax/alpamon/v2/pkg/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// proxyChildTarget names the URL a re-executed test binary requests. Go reads
// the proxy environment once per process, so each case runs in a fresh one.
const proxyChildTarget = "ALPAMON_TEST_PROXY_TARGET"

var proxyEnvNames = []string{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "NO_PROXY", "no_proxy", "REQUEST_METHOD"}

// recordingProxy accepts connections and records the request line of each.
// It answers a plain request with 200 and refuses a CONNECT, which is enough
// to show which requests reached it.
func recordingProxy(t *testing.T) (string, <-chan string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	seen := make(chan string, 4)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				req, err := http.ReadRequest(bufio.NewReader(conn))
				if err != nil {
					return
				}
				if req.Method == http.MethodConnect {
					seen <- req.Method + " " + req.Host
					_, _ = conn.Write([]byte("HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n"))
					return
				}
				seen <- req.Method + " " + req.URL.String()
				_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"))
			}()
		}
	}()
	return "http://" + ln.Addr().String(), seen
}

// runProxyChild runs test in a new process with no proxy variables except env.
func runProxyChild(t *testing.T, test, target string, env ...string) string {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^"+test+"$", "-test.count=1", "-test.v")
	for _, kv := range os.Environ() {
		name, _, _ := strings.Cut(kv, "=")
		if !containsFold(proxyEnvNames, name) {
			cmd.Env = append(cmd.Env, kv)
		}
	}
	cmd.Env = append(cmd.Env, proxyChildTarget+"="+target)
	cmd.Env = append(cmd.Env, env...)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "%s", out)
	return string(out)
}

func containsFold(names []string, name string) bool {
	for _, n := range names {
		if strings.EqualFold(n, name) {
			return true
		}
	}
	return false
}

// TestNewHTTPClient_ProxyEnvironment covers the client the signing key fetch
// and the server session share.
func TestNewHTTPClient_ProxyEnvironment(t *testing.T) {
	if target := os.Getenv(proxyChildTarget); target != "" {
		req, err := http.NewRequest(http.MethodGet, target, nil)
		require.NoError(t, err)
		var proxy *url.URL
		if p := transport().Proxy; p != nil {
			proxy, err = p(req)
			require.NoError(t, err)
		}
		if proxy == nil {
			t.Log("PROXY=direct")
			return
		}
		t.Log("PROXY=" + proxy.String())
		client := NewHTTPClient()
		client.Timeout = 5 * time.Second
		if resp, err := client.Get(target); err == nil {
			_ = resp.Body.Close()
		}
		return
	}

	proxyURL, seen := recordingProxy(t)
	tests := []struct {
		name     string
		target   string
		env      []string
		wantSeen string // empty: the proxy must not be used
	}{
		{
			name:     "HTTPS_PROXY carries an https request as a CONNECT",
			target:   "https://ai.example.test/api/commands/public-key/",
			env:      []string{"HTTPS_PROXY=" + proxyURL},
			wantSeen: "CONNECT ai.example.test:443",
		},
		{
			name:     "HTTP_PROXY carries an http request",
			target:   "http://ai.example.test/api/commands/public-key/",
			env:      []string{"HTTP_PROXY=" + proxyURL},
			wantSeen: "GET http://ai.example.test/api/commands/public-key/",
		},
		{
			name:   "NO_PROXY exempts a host",
			target: "https://ai.example.test/api/commands/public-key/",
			env:    []string{"HTTPS_PROXY=" + proxyURL, "NO_PROXY=ai.example.test"},
		},
		{
			name:   "no proxy environment dials directly",
			target: "https://alpacon.ai/api/commands/public-key/",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out := runProxyChild(t, "TestNewHTTPClient_ProxyEnvironment", tt.target, tt.env...)
			if tt.wantSeen == "" {
				assert.Contains(t, out, "PROXY=direct")
				select {
				case got := <-seen:
					assert.Failf(t, "the proxy must not be used", "it received %q", got)
				default:
				}
				return
			}
			assert.Contains(t, out, "PROXY="+proxyURL)
			select {
			case got := <-seen:
				assert.Equal(t, tt.wantSeen, got)
			case <-time.After(5 * time.Second):
				t.Fatal("the request never reached the proxy")
			}
		})
	}
}

// TestNewTransport_ChangesOnlyTheProxy pins every other transport setting to
// what it was before the transport honored the proxy environment.
func TestNewTransport_ChangesOnlyTheProxy(t *testing.T) {
	setSettings(t, config.Settings{SSLVerify: true})

	got, err := NewTransport()
	require.NoError(t, err)
	require.NotNil(t, got.Proxy)
	assert.True(t, isProxyFromEnvironment(got.Proxy))

	got.Proxy = nil
	assert.Equal(t, &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: false},
		MaxIdleConnsPerHost: maxIdleConnsPerHost,
		IdleConnTimeout:     idleConnTimeout,
	}, got)
}

func TestPut_HonorsTheProxyEnvironment(t *testing.T) {
	setSettings(t, config.Settings{SSLVerify: true})

	rt := WithoutKeepAlives(transport())
	tr, ok := rt.(*http.Transport)
	require.True(t, ok)
	assert.True(t, isProxyFromEnvironment(tr.Proxy))
}

// isProxyFromEnvironment reports whether proxy is http.ProxyFromEnvironment.
func isProxyFromEnvironment(proxy func(*http.Request) (*url.URL, error)) bool {
	return proxy != nil && reflect.ValueOf(proxy).Pointer() == reflect.ValueOf(http.ProxyFromEnvironment).Pointer()
}
