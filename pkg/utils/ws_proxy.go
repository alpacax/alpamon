package utils

import (
	"net/http"
	"net/url"
	"sync"

	"github.com/rs/zerolog/log"
)

// websocketProxySchemes are the proxy schemes gorilla/websocket can dial
// through; it refuses any other with "proxy: unknown scheme".
var websocketProxySchemes = map[string]bool{"http": true, "socks5": true}

type websocketProxy struct {
	resolve  func(*http.Request) (*url.URL, error)
	warnOnce sync.Once
}

var envWebsocketProxy = &websocketProxy{resolve: http.ProxyFromEnvironment}

// WebsocketProxy is the proxy func for WebSocket dialers. It follows the
// proxy environment like the REST clients, except that a proxy whose scheme
// WebSocket connections do not support is dropped, with one warning per
// process, so the dial goes direct instead of failing.
func WebsocketProxy(req *http.Request) (*url.URL, error) {
	return envWebsocketProxy.proxy(req)
}

func (p *websocketProxy) proxy(req *http.Request) (*url.URL, error) {
	proxyURL, err := p.resolve(req)
	if err != nil || proxyURL == nil || websocketProxySchemes[proxyURL.Scheme] {
		return proxyURL, err
	}
	p.warnOnce.Do(func() {
		// Name the variable and the scheme only: the URL may carry credentials.
		name := "HTTP_PROXY"
		if req.URL.Scheme == "https" || req.URL.Scheme == "wss" {
			name = "HTTPS_PROXY"
		}
		log.Warn().Msgf("%s uses the %s scheme, which WebSocket connections do not support; WebSocket connections dial directly.", name, proxyURL.Scheme)
	})
	return nil, nil
}
