package utils

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
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

var (
	transportMu     sync.Mutex
	sharedTransport *http.Transport
)

// NewHTTPClient returns a new client over one shared transport.
// A transport whose CA file failed to load or parse is not shared, so the next call retries the read.
func NewHTTPClient() *http.Client {
	transportMu.Lock()
	defer transportMu.Unlock()
	if sharedTransport != nil {
		return &http.Client{Transport: sharedTransport}
	}
	transport, ok := newTransport()
	if ok {
		sharedTransport = transport
	}
	return &http.Client{Transport: transport}
}

func newTransport() (*http.Transport, bool) {
	tlsConfig := &tls.Config{
		InsecureSkipVerify: !config.GlobalSettings.SSLVerify,
	}
	ok := true

	if config.GlobalSettings.CaCert != "" {
		caCertPool := x509.NewCertPool()
		if caCert, err := os.ReadFile(config.GlobalSettings.CaCert); err == nil {
			if !caCertPool.AppendCertsFromPEM(caCert) {
				log.Error().Msg("No PEM certificate found in the CA file.")
				ok = false
			}
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
	// A streamed PUT is never retried, so it must not land on an idle connection the server just closed.
	transport := client.Transport.(*http.Transport).Clone()
	transport.DisableKeepAlives = true
	client.Transport = transport

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

// ParseRetryAfter reads a Retry-After value in either form RFC 9110 allows,
// delay-seconds or an HTTP date. It returns zero when the header is absent or
// unusable, and caps the result at maxWait.
func ParseRetryAfter(value string, now time.Time, maxWait time.Duration) time.Duration {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0
	}
	var d time.Duration
	if seconds, err := strconv.ParseInt(value, 10, 64); err == nil {
		if seconds <= 0 {
			return 0
		}
		if seconds > int64(maxWait/time.Second) {
			return maxWait
		}
		d = time.Duration(seconds) * time.Second
	} else if at, err := http.ParseTime(value); err == nil {
		d = at.Sub(now)
	}
	if d <= 0 {
		return 0
	}
	return min(d, maxWait)
}
