package utils

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
)

// IsServerURL reports whether u has server's scheme and host:port, the only
// URLs the agent sends its key to.
func IsServerURL(u, server *url.URL) bool {
	return strings.EqualFold(u.Scheme, server.Scheme) && strings.EqualFold(u.Host, server.Host)
}

// ServerOnlyAuthorization returns an http.Client CheckRedirect that follows up
// to 10 redirects, as the default policy does, and drops the Authorization
// header from any hop that is not on server. Go's own policy keeps the header
// across a port change, a subdomain and a switch from https to http.
func ServerOnlyAuthorization(server *url.URL) func(*http.Request, []*http.Request) error {
	return func(req *http.Request, via []*http.Request) error {
		if len(via) >= 10 {
			return errors.New("stopped after 10 redirects")
		}
		if !IsServerURL(req.URL, server) {
			req.Header.Del("Authorization")
		}
		return nil
	}
}
