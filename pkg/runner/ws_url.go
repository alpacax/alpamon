package runner

import (
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/alpacax/alpamon/v2/pkg/config"
	"github.com/alpacax/alpamon/v2/pkg/utils"
)

// unknownServerHost stands in when a URL has no host to report, either because
// it does not parse or because it carries no authority.
const unknownServerHost = "invalid"

// validateWebSocketURL resolves a socket URL from Alpacon against the configured
// server URL; see resolveWebSocketURL.
func validateWebSocketURL(rawURL string) (string, error) {
	return resolveWebSocketURL(rawURL, config.GlobalSettings.ServerURL)
}

// resolveWebSocketURL returns the URL to dial for a socket URL sent by Alpacon.
// A path-only target is joined to serverURL. An absolute URL must use the ws/wss
// scheme derived from serverURL and name the same host. The result is rebuilt
// from serverURL's scheme and host plus the sent path and query, so it can only
// point at the configured server.
func resolveWebSocketURL(rawURL, serverURL string) (string, error) {
	server, err := url.Parse(serverURL)
	if err != nil {
		return "", fmt.Errorf("invalid server URL: %w", err)
	}

	var expectedScheme string
	switch strings.ToLower(server.Scheme) {
	case "http":
		expectedScheme = "ws"
	case "https":
		expectedScheme = "wss"
	default:
		return "", fmt.Errorf("unsupported server URL scheme: %s", server.Scheme)
	}

	parsed, err := utils.ResolveServerURL(rawURL, server, expectedScheme)
	if err != nil {
		return "", fmt.Errorf("invalid WebSocket URL: %w", err)
	}

	if !strings.EqualFold(parsed.Scheme, expectedScheme) {
		return "", fmt.Errorf("WebSocket URL scheme %q does not match expected scheme %q", parsed.Scheme, expectedScheme)
	}

	if !strings.EqualFold(parsed.Hostname(), server.Hostname()) {
		return "", fmt.Errorf("WebSocket URL host %q does not match server host %q", parsed.Hostname(), server.Hostname())
	}

	// Reconstruct URL using trusted sources for scheme and host to prevent SSRF.
	sanitized := &url.URL{
		Scheme:   expectedScheme,
		Host:     server.Host,
		Path:     parsed.Path,
		RawPath:  parsed.RawPath,
		RawQuery: parsed.RawQuery,
	}
	return sanitized.String(), nil
}

// ServerHostFromURL returns the host of a session URL. Tunnel and FTP URLs carry
// a session-scoped token in the path, and agent logs are shipped off-host, so the
// host is the only part of such a URL that may be logged. A path-only URL
// reports the configured server's host, which is where it resolves.
func ServerHostFromURL(rawURL string) string {
	return serverHostFor(rawURL, config.GlobalSettings.ServerURL)
}

// serverHostFor is ServerHostFromURL against an explicit server URL, for the
// WebFTP worker, which runs without the agent's configuration.
func serverHostFor(rawURL, serverURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return unknownServerHost
	}
	if parsed.Host == "" && parsed.Scheme == "" && strings.HasPrefix(rawURL, "/") {
		parsed, err = url.Parse(serverURL)
		if err != nil {
			return unknownServerHost
		}
	}
	if parsed.Host == "" {
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
