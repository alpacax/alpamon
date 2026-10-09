package utils

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/alpacax/alpamon/v2/pkg/config"
	"github.com/rs/zerolog/log"
)

const (
	// MaxIdleConnsPerHost covers the reporter threads plus collector workers posting to one host.
	MaxIdleConnsPerHost = 16
	IdleConnTimeout     = 90 * time.Second
)

type transportKey struct {
	sslVerify bool
	caCert    string
}

var (
	transportMu     sync.Mutex
	cachedKey       transportKey
	cachedTransport *http.Transport
)

// NewHTTPClient returns a new client that shares one transport per (SSLVerify, CaCert) setting.
// A transport whose CA file failed to load is not shared, so the next call retries the read.
func NewHTTPClient() *http.Client {
	key := transportKey{
		sslVerify: config.GlobalSettings.SSLVerify,
		caCert:    config.GlobalSettings.CaCert,
	}

	transportMu.Lock()
	defer transportMu.Unlock()
	if cachedTransport != nil && cachedKey == key {
		return &http.Client{Transport: cachedTransport}
	}
	transport, ok := newTransport(key)
	if ok {
		cachedTransport, cachedKey = transport, key
	}
	return &http.Client{Transport: transport}
}

func newTransport(key transportKey) (*http.Transport, bool) {
	tlsConfig := &tls.Config{
		InsecureSkipVerify: !key.sslVerify,
	}
	ok := true

	if key.caCert != "" {
		caCertPool := x509.NewCertPool()
		if caCert, err := os.ReadFile(key.caCert); err == nil {
			caCertPool.AppendCertsFromPEM(caCert)
			tlsConfig.RootCAs = caCertPool
		} else {
			log.Error().Err(err).Msg("Failed to read CA certificate.")
			ok = false
		}
	}

	return &http.Transport{
		TLSClientConfig:     tlsConfig,
		MaxIdleConnsPerHost: MaxIdleConnsPerHost,
		IdleConnTimeout:     IdleConnTimeout,
	}, ok
}

// putMaxResponseSize caps response bodies for Put. Read putMaxResponseSize+1
// bytes so an over-cap response can be detected explicitly instead of silently
// truncating (which would hide server error details).
const putMaxResponseSize = 1 << 20 // 1 MiB

// Put issues a PUT request. Pass contentLength=-1 to force chunked transfer.
//
// codeql[go/request-forgery]: Intentional - HTTP client for admin-specified URLs
func Put(url string, body io.Reader, contentLength int64, timeout time.Duration) ([]byte, int, error) {
	req, err := http.NewRequest(http.MethodPut, url, body) // lgtm[go/request-forgery]
	if err != nil {
		return nil, 0, err
	}
	// Overwrite unconditionally: http.NewRequest auto-fills ContentLength for
	// bytes/strings readers, which would defeat a caller's -1 chunked opt-in.
	req.ContentLength = contentLength

	client := NewHTTPClient()
	client.Timeout = timeout

	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, HostOnlyURLError(err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, putMaxResponseSize+1))
	if err != nil {
		return nil, resp.StatusCode, err
	}
	if int64(len(respBody)) > putMaxResponseSize {
		return nil, resp.StatusCode, fmt.Errorf("PUT response too large (>%d bytes)", putMaxResponseSize)
	}

	return respBody, resp.StatusCode, nil
}
