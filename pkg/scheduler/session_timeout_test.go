package scheduler

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// deadlineRecorder answers every request and records the deadline it carried.
type deadlineRecorder struct {
	deadline time.Time
	ok       bool
}

func (d *deadlineRecorder) RoundTrip(req *http.Request) (*http.Response, error) {
	d.deadline, d.ok = req.Context().Deadline()
	return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader("ok")), Request: req}, nil
}

func TestSession_AppliesTheTimeoutAsARealDuration(t *testing.T) {
	const timeout = 2 * time.Second

	calls := map[string]func(*Session) error{
		"Get":    func(s *Session) error { _, _, err := s.Get("/x", timeout); return err },
		"Post":   func(s *Session) error { _, _, err := s.Post("/x", nil, timeout); return err },
		"Patch":  func(s *Session) error { _, _, err := s.Patch("/x", nil, timeout); return err },
		"Delete": func(s *Session) error { _, _, err := s.Delete("/x", nil, timeout); return err },
		"PostWithContext": func(s *Session) error {
			_, _, _, err := s.PostWithContext(context.Background(), "/x", nil, timeout)
			return err
		},
		"RequestWithHeaders": func(s *Session) error {
			_, _, _, err := s.RequestWithHeaders(http.MethodGet, "/x", nil, timeout, nil)
			return err
		},
		"MultipartRequest": func(s *Session) error {
			_, _, err := s.MultipartRequest("/x", strings.NewReader("x"), "text/plain", 1, timeout)
			return err
		},
	}

	for name, call := range calls {
		t.Run(name, func(t *testing.T) {
			rec := &deadlineRecorder{}
			session := &Session{BaseURL: "http://alpacon.test", Client: &http.Client{Transport: rec}}
			start := time.Now()

			err := call(session)

			require.NoError(t, err)
			require.True(t, rec.ok, "the request carries a deadline")
			assert.WithinRange(t, rec.deadline, start, start.Add(timeout+time.Second))
		})
	}
}
