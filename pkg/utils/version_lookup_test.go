package utils

import (
	"net/http"
	"testing"
)

// TestNewVersionLookupClient_NoProxy pins the default: without a proxy URL the
// client uses the default transport (nil Transport), which respects the
// process-level proxy environment when present.
func TestNewVersionLookupClient_NoProxy(t *testing.T) {
	client := NewVersionLookupClient("")
	if client.Transport != nil {
		t.Errorf("expected default transport (nil), got %T", client.Transport)
	}
}

// TestNewVersionLookupClient_WithProxy verifies a per-request transport is
// pinned to the payload-provided proxy, without touching process globals.
func TestNewVersionLookupClient_WithProxy(t *testing.T) {
	client := NewVersionLookupClient("http://proxy.internal:3128")

	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("expected *http.Transport, got %T", client.Transport)
	}
	req, err := http.NewRequest("GET", "https://api.github.com/repos/alpacax/alpamon/releases/latest", nil)
	if err != nil {
		t.Fatalf("failed to build request: %v", err)
	}
	proxy, err := transport.Proxy(req)
	if err != nil {
		t.Fatalf("proxy func returned error: %v", err)
	}
	if proxy == nil || proxy.String() != "http://proxy.internal:3128" {
		t.Errorf("expected proxy http://proxy.internal:3128, got %v", proxy)
	}
}

// TestNewVersionLookupClient_InvalidProxy verifies an unparsable proxy URL
// falls back to the default transport instead of failing the lookup.
func TestNewVersionLookupClient_InvalidProxy(t *testing.T) {
	for _, invalid := range []string{"http://[::1", "not a url"} {
		client := NewVersionLookupClient(invalid)
		if client.Transport != nil {
			t.Errorf("proxy %q: expected fallback to default transport (nil), got %T", invalid, client.Transport)
		}
	}
}
