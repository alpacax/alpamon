package utils

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// ResolveServerURL parses rawURL, a URL Alpacon sent the agent to reach, against
// server, the configured server URL.
//
// A path-only target ("/path", optionally with a query) resolves to server's
// host with the given scheme. An absolute URL is returned as parsed; callers
// apply their own scheme and host rules to it. Inputs whose meaning depends on
// who parses them are refused: a scheme-relative URL ("//host/path"), a path
// that does not start with "/", userinfo, and a backslash anywhere.
//
// Errors never quote rawURL, which may carry a session token in its path.
func ResolveServerURL(rawURL string, server *url.URL, scheme string) (*url.URL, error) {
	if strings.ContainsRune(rawURL, '\\') {
		return nil, errors.New("URL contains a backslash")
	}
	if strings.HasPrefix(rawURL, "//") {
		return nil, errors.New("scheme-relative URL is not allowed")
	}

	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil, errors.New("URL does not parse")
	}
	if parsed.User != nil {
		return nil, errors.New("URL with userinfo is not allowed")
	}

	if parsed.Scheme != "" {
		if parsed.Host == "" {
			return nil, fmt.Errorf("%s URL has no host", parsed.Scheme)
		}
		return parsed, nil
	}

	if !strings.HasPrefix(rawURL, "/") {
		return nil, errors.New("path-only URL must start with /")
	}
	if server == nil || server.Host == "" {
		return nil, errors.New("no server host to resolve a path-only URL against")
	}
	return &url.URL{
		Scheme:   scheme,
		Host:     server.Host,
		Path:     parsed.Path,
		RawPath:  parsed.RawPath,
		RawQuery: parsed.RawQuery,
	}, nil
}
