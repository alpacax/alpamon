package cloud

import (
	"fmt"
	"io"
	"net/http"
	"time"
)

// readLimitedN reads up to max bytes from r and errors out if the payload
// exceeds the cap. Defends against a misbehaving / spoofed metadata responder
// filling memory with garbage. Real IMDS responses are tiny (well under 8 KB).
func readLimitedN(r io.Reader, max int64) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(r, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > max {
		return nil, fmt.Errorf("response exceeds %d bytes", max)
	}
	return body, nil
}

// newIMDSClient returns an *http.Client configured for link-local IMDS reads.
// Two security hardenings beyond http.DefaultClient:
//
//  1. Proxy is explicitly disabled. IMDS lives on link-local addresses
//     (169.254.169.254 / metadata.google.internal) that must never traverse a
//     proxy. Honoring HTTP_PROXY/HTTPS_PROXY env vars would leak host metadata
//     to whatever the operator's shell configured.
//  2. Redirects are disabled. A spoofed or compromised metadata responder
//     issuing a 30x could otherwise direct the client to an off-host URL and
//     exfiltrate request headers (notably the IMDSv2 session token for AWS).
//     CheckRedirect returns http.ErrUseLastResponse so callers see the 30x
//     status as a non-200 and fail closed.
func newIMDSClient(timeout time.Duration) *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	return &http.Client{
		Timeout:   timeout,
		Transport: transport,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}
