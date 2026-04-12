package runner

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/alpacax/alpamon/pkg/config"
)

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
