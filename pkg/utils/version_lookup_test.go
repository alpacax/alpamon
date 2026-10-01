package utils

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewVersionLookupClient_NoProxy pins the default: without a proxy URL the
// client uses the default transport (nil Transport), which respects the
// process-level proxy environment when present.
func TestNewVersionLookupClient_NoProxy(t *testing.T) {
	client := NewVersionLookupClient("")
	assert.True(t, client.Transport == nil, "expected default transport (nil), got %T", client.Transport)
}

// TestNewVersionLookupClient_WithProxy verifies a per-request transport is
// pinned to the payload-provided proxy, without touching process globals.
func TestNewVersionLookupClient_WithProxy(t *testing.T) {
	client := NewVersionLookupClient("http://proxy.internal:3128")

	transport, ok := client.Transport.(*http.Transport)
	require.True(t, ok, "expected *http.Transport, got %T", client.Transport)
	req, err := http.NewRequest("GET", "https://api.github.com/repos/alpacax/alpamon/releases/latest", nil)
	require.NoError(t, err, "failed to build request")
	proxy, err := transport.Proxy(req)
	require.NoError(t, err, "proxy func returned error")
	if assert.NotNil(t, proxy, "expected proxy http://proxy.internal:3128") {
		assert.Equal(t, "http://proxy.internal:3128", proxy.String())
	}
}

// TestNewVersionLookupClient_InvalidProxy verifies an unparsable proxy URL
// falls back to the default transport instead of failing the lookup.
func TestNewVersionLookupClient_InvalidProxy(t *testing.T) {
	for _, invalid := range []string{"http://[::1", "not a url"} {
		client := NewVersionLookupClient(invalid)
		assert.True(t, client.Transport == nil, "proxy %q: expected fallback to default transport (nil), got %T", invalid, client.Transport)
	}
}
