package utils

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
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

// Idle pool settings for the session transport and NewHTTPClient.
const (
	// Covers the reporter threads and collector workers posting to Alpacon, plus downloads.
	maxIdleConnsPerHost = 16
	idleConnTimeout     = 90 * time.Second
)

var (
	transportMu     sync.Mutex
	sharedTransport *http.Transport
)

// NewHTTPClient returns a new client over one shared transport.
// A transport whose CA file failed to load or parse is not shared, so the next call retries the read.
func NewHTTPClient() *http.Client {
	return &http.Client{Transport: transport()}
}

func transport() *http.Transport {
	transportMu.Lock()
	defer transportMu.Unlock()
	if sharedTransport != nil {
		return sharedTransport
	}
	t, err := NewTransport()
	if err != nil {
		log.Error().Err(err).Msg("Failed to load the CA certificate.")
		return t
	}
	sharedTransport = t
	return t
}

// NewTransport builds a transport from the TLS settings. When the CA file cannot be
// read or holds no PEM certificate, it returns the error with a transport that trusts no CA.
func NewTransport() (*http.Transport, error) {
	tlsConfig := &tls.Config{
		InsecureSkipVerify: !config.GlobalSettings.SSLVerify,
	}
	var err error
	if config.GlobalSettings.CaCert != "" {
		tlsConfig.RootCAs = x509.NewCertPool()
		var caCert []byte
		if caCert, err = os.ReadFile(config.GlobalSettings.CaCert); err == nil && !tlsConfig.RootCAs.AppendCertsFromPEM(caCert) {
			err = errors.New("no PEM certificate found in the CA file")
		}
	}

	return &http.Transport{
		TLSClientConfig:     tlsConfig,
		MaxIdleConnsPerHost: maxIdleConnsPerHost,
		IdleConnTimeout:     idleConnTimeout,
	}, err
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

	// A streamed PUT is never retried, so it must not land on an idle connection the server just closed.
	t := transport().Clone()
	t.DisableKeepAlives = true
	client := &http.Client{Transport: t, Timeout: timeout}

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
