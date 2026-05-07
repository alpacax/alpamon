package utils

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/alpacax/alpamon/pkg/config"
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

// codeql[go/request-forgery]: Intentional - HTTP client for admin-specified URLs
func Put(url string, body io.Reader, contentLength int64, timeout time.Duration) ([]byte, int, error) {
	req, err := http.NewRequest(http.MethodPut, url, body) // lgtm[go/request-forgery]
	if err != nil {
		return nil, 0, err
	}
	if contentLength >= 0 {
		req.ContentLength = contentLength
	}

	client := NewHTTPClient()
	client.Timeout = timeout

	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, err
	}

	return respBody, resp.StatusCode, nil
}
