package exposure

import (
	"context"
	"net/http"
	"time"
)

// Poster is the part of scheduler.Session the transport uses. These calls
// bypass the request queue: its reporter logs response bodies on failure,
// which this endpoint pair must never do.
type Poster interface {
	PostExposure(ctx context.Context, url string, body any, timeout time.Duration) ([]byte, int, http.Header, error)
}
