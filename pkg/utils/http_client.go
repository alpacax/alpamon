package utils

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/alpacax/alpamon/v2/pkg/config"
	"github.com/rs/zerolog/log"
)

// NewHTTPClient creates an HTTP client with TLS configuration from global settings
func NewHTTPClient() *http.Client {
	tlsConfig := &tls.Config{
		InsecureSkipVerify: !config.GlobalSettings.SSLVerify,
	}

	if config.GlobalSettings.CaCert != "" {
		caCertPool := x509.NewCertPool()
		if caCert, err := os.ReadFile(config.GlobalSettings.CaCert); err == nil {
			caCertPool.AppendCertsFromPEM(caCert)
			tlsConfig.RootCAs = caCertPool
		} else {
			log.Error().Err(err).Msg("Failed to read CA certificate.")
		}
	}

	return &http.Client{
		Transport: &http.Transport{TLSClientConfig: tlsConfig},
	}
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
		return nil, 0, err
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
