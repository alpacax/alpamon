package runner

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"

	"golang.org/x/net/proxy"
)

// OpenFtpProxySocket completes the proxy handshake before passing the connection to a worker.
func OpenFtpProxySocket(ctx context.Context, target, server, rawProxy string) (*os.File, error) {
	resolved, err := resolveWebSocketURL(target, server)
	if err != nil {
		return nil, err
	}
	dest, err := url.Parse(resolved)
	if err != nil {
		return nil, ErrFtpProxyConfig
	}
	port := dest.Port()
	if port == "" {
		port = "443"
		if dest.Scheme == "ws" {
			port = "80"
		}
	}
	address := net.JoinHostPort(dest.Hostname(), port)
	endpoint, err := url.Parse(rawProxy)
	if err != nil {
		return nil, ErrFtpProxyConfig
	}
	ctx, cancel := context.WithTimeout(ctx, handshakeTimeout)
	defer cancel()
	dialer := &net.Dialer{}
	proxyPort := endpoint.Port()
	switch endpoint.Scheme {
	case "http":
		if proxyPort == "" {
			proxyPort = "80"
		}
	case "socks5":
		if proxyPort == "" {
			proxyPort = "1080"
		}
	default:
		return nil, ErrFtpProxyConfig
	}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(endpoint.Hostname(), proxyPort))
	if err != nil {
		return nil, errors.New("FTP proxy connection failed")
	}
	defer func() { _ = conn.Close() }()
	if endpoint.Scheme == "socks5" {
		socks, err := proxy.FromURL(endpoint, connectedProxy{conn})
		if err != nil {
			return nil, ErrFtpProxyConfig
		}
		if _, err := socks.(proxy.ContextDialer).DialContext(ctx, "tcp", address); err != nil {
			return nil, errors.New("FTP SOCKS proxy connection failed")
		}
	}
	if endpoint.Scheme == "http" {
		stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
		defer stop()
		deadline, _ := ctx.Deadline()
		if err := conn.SetDeadline(deadline); err != nil {
			return nil, err
		}
		request := http.Request{Method: http.MethodConnect, URL: &url.URL{Opaque: address}, Host: address, Header: make(http.Header)}
		if endpoint.User != nil {
			password, _ := endpoint.User.Password()
			request.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(endpoint.User.Username()+":"+password)))
		}
		if err := request.Write(conn); err != nil {
			return nil, errors.New("FTP proxy request failed")
		}
		resp, err := http.ReadResponse(bufio.NewReader(io.LimitReader(conn, 64<<10)), &request)
		if err != nil {
			return nil, errors.New("invalid FTP proxy response")
		}
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("FTP proxy returned HTTP %d", resp.StatusCode)
		}
		if err := conn.SetDeadline(time.Time{}); err != nil {
			return nil, err
		}
	}
	tcp, ok := conn.(*net.TCPConn)
	if !ok {
		return nil, errors.New("FTP proxy did not return a TCP socket")
	}
	return tcp.File()
}

// The TCP socket stays with the agent while the SOCKS dialer negotiates over it.
type connectedProxy struct{ conn net.Conn }

func (p connectedProxy) Dial(string, string) (net.Conn, error) { return p.conn, nil }
