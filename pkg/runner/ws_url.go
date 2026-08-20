package runner

import (
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/alpacax/alpamon/v2/pkg/config"
)

// unknownServerHost stands in when a URL has no host to report, either because
// it does not parse or because it carries no authority.
const unknownServerHost = "invalid"

// validateWebSocketURL checks that the given URL uses the correct ws/wss scheme
// derived from the configured server URL and that its host matches the server.
// It returns a sanitized URL string reconstructed from the parsed components.
func validateWebSocketURL(rawURL string) (string, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "", fmt.Errorf("invalid WebSocket URL: %w", err)
	}

	serverURL, err := url.Parse(config.GlobalSettings.ServerURL)
	if err != nil {
		return "", fmt.Errorf("invalid server URL: %w", err)
	}

	var expectedScheme string
	switch strings.ToLower(serverURL.Scheme) {
	case "http":
		expectedScheme = "ws"
	case "https":
		expectedScheme = "wss"
	default:
		return "", fmt.Errorf("unsupported server URL scheme: %s", serverURL.Scheme)
	}

	if !strings.EqualFold(parsed.Scheme, expectedScheme) {
		return "", fmt.Errorf("WebSocket URL scheme %q does not match expected scheme %q", parsed.Scheme, expectedScheme)
	}

	if !strings.EqualFold(parsed.Hostname(), serverURL.Hostname()) {
		return "", fmt.Errorf("WebSocket URL host %q does not match server host %q", parsed.Hostname(), serverURL.Hostname())
	}

	// Reconstruct URL using trusted sources for scheme and host to prevent SSRF.
	sanitized := &url.URL{
		Scheme:   expectedScheme,
		Host:     serverURL.Host,
		Path:     parsed.Path,
		RawQuery: parsed.RawQuery,
	}
	return sanitized.String(), nil
}

// ServerHostFromURL returns the host of a session URL. Tunnel and FTP URLs carry
// a session-scoped token in the path, and agent logs are shipped off-host, so the
// host is the only part of such a URL that may be logged.
func ServerHostFromURL(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Host == "" {
		return unknownServerHost
	}
	return parsed.Host
}

// sanitizeURLError rewrites a *url.Error to name the host instead of the whole
// URL. net/http and net/url put the URL they were given into these errors, and
// the tunnel URL carries a session-scoped token that must stay out of the log.
func sanitizeURLError(err error) error {
	var urlErr *url.Error
	if !errors.As(err, &urlErr) {
		return err
	}
	return fmt.Errorf("%s %s: %w", urlErr.Op, ServerHostFromURL(urlErr.URL), urlErr.Err)
}
