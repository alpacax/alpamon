package updater

import (
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakePoster struct {
	status int
	err    error
	urls   []string
	bodies []any
}

func (p *fakePoster) Post(url string, body any, _ time.Duration) ([]byte, int, error) {
	p.urls = append(p.urls, url)
	p.bodies = append(p.bodies, body)
	return nil, p.status, p.err
}

func TestSendReport(t *testing.T) {
	r := Report{AttemptID: "a1", FromVersion: "2.4.0", ToVersion: "2.5.0", Outcome: OutcomeFailed, ErrorClass: ClassDigestMismatch}

	tests := []struct {
		name      string
		poster    *fakePoster
		delivered bool
	}{
		{"accepted", &fakePoster{status: http.StatusCreated}, true},
		{"server predates the endpoint", &fakePoster{status: http.StatusNotFound}, true},
		{"endpoint gone", &fakePoster{status: http.StatusGone}, true},
		{"rejected as invalid", &fakePoster{status: http.StatusBadRequest}, false},
		{"server error", &fakePoster{status: http.StatusBadGateway}, false},
		{"network error", &fakePoster{err: errors.New("dial tcp: refused")}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.delivered, SendReport(tt.poster, r))
			require.Len(t, tt.poster.urls, 1)
			assert.Equal(t, ReportURL, tt.poster.urls[0])
			assert.Equal(t, r, tt.poster.bodies[0])
		})
	}

	t.Run("no attempt id sends nothing", func(t *testing.T) {
		p := &fakePoster{status: http.StatusOK}
		assert.True(t, SendReport(p, Report{Outcome: OutcomeSucceeded}))
		assert.Empty(t, p.urls)
	})
	t.Run("nil poster", func(t *testing.T) {
		assert.True(t, SendReport(nil, r))
	})
}
