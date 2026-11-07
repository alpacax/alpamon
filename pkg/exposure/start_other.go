//go:build !linux

package exposure

import (
	"context"
	"net/http"
	"time"
)

// Supported reports whether this build collects and sends the exposure
// report. Only Linux does in this version.
const Supported = false

// Poster is the part of scheduler.Session the transport would use.
type Poster interface {
	PostExposure(ctx context.Context, url string, body any, timeout time.Duration) ([]byte, int, http.Header, error)
}

// Start does nothing on this platform: neither endpoint is ever called.
func Start(context.Context, Poster) {}

// Trigger does nothing on this platform.
func Trigger() {}
