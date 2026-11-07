//go:build !linux

package exposure

import (
	"context"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

type countingPoster struct{ calls atomic.Int32 }

func (p *countingPoster) PostExposure(context.Context, string, any, time.Duration) ([]byte, int, http.Header, error) {
	p.calls.Add(1)
	return nil, http.StatusOK, nil, nil
}

// Off Linux the exposure endpoints are never called, whatever triggers.
func TestOtherPlatformsNeverCallTheEndpoints(t *testing.T) {
	assert.False(t, Supported)
	p := &countingPoster{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	Start(ctx, p)
	for range 10 {
		Trigger()
	}
	time.Sleep(100 * time.Millisecond)
	assert.Zero(t, p.calls.Load())
}
