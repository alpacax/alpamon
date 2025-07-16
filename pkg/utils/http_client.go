package utils

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/alpacax/alpamon/pkg/config"
	"github.com/rs/zerolog/log"
)

func Put(url string, body bytes.Buffer, timeout time.Duration) ([]byte, int, error) {
	req, err := http.NewRequest(http.MethodPut, url, &body)
	if err != nil {
		return nil, 0, err
	}

	client := &http.Client{Timeout: timeout}

	tlsConfig := &tls.Config{}
	if config.GlobalSettings.CaCert != "" {
		caCertPool := x509.NewCertPool()
		caCert, err := os.ReadFile(config.GlobalSettings.CaCert)
		if err != nil {
			log.Error().Err(err).Msg("Failed to read CA certificate.")
		}
		caCertPool.AppendCertsFromPEM(caCert)
		tlsConfig.RootCAs = caCertPool
	}

	tlsConfig.InsecureSkipVerify = !config.GlobalSettings.SSLVerify
	client.Transport = &http.Transport{
		TLSClientConfig: tlsConfig,
	}

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
