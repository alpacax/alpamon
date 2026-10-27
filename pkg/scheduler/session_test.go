package scheduler

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alpacax/alpamon/v2/pkg/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInitSession_GivenConcurrentBursts_WhenSecondBurstFires_ThenIdleConnectionsAreReused(t *testing.T) {
	const burst = 8

	var newConns, arrived int32
	release := make(chan struct{})
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&arrived, 1) == burst {
			close(release)
		}
		select {
		case <-release:
		case <-time.After(5 * time.Second):
		}
		_, _ = w.Write([]byte("ok"))
	}))
	server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			atomic.AddInt32(&newConns, 1)
		}
	}
	server.StartTLS()
	t.Cleanup(server.Close)

	saved := config.GlobalSettings
	t.Cleanup(func() { config.GlobalSettings = saved })
	config.GlobalSettings = config.Settings{ServerURL: server.URL, SSLVerify: false, ID: "test", Key: "test"}
	session := InitSession()

	fire := func() {
		var wg sync.WaitGroup
		for range burst {
			wg.Go(func() {
				body, status, err := session.Get("/x", 10*time.Second)
				assert.NoError(t, err)
				assert.Equal(t, http.StatusOK, status)
				assert.Equal(t, "ok", string(body))
			})
		}
		wg.Wait()
	}

	fire()
	require.Equal(t, int32(burst), atomic.LoadInt32(&newConns), "first burst opens one connection per request")

	atomic.StoreInt32(&arrived, burst) // later requests pass the barrier immediately
	fire()

	assert.Equal(t, int32(burst), atomic.LoadInt32(&newConns))
}

type deadlineRecorder struct {
	called   bool
	deadline time.Time
	ok       bool
}

func (d *deadlineRecorder) RoundTrip(req *http.Request) (*http.Response, error) {
	d.called = true
	d.deadline, d.ok = req.Context().Deadline()
	return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader("ok")), Request: req}, nil
}

func sessionCalls(timeout time.Duration) map[string]func(*Session) error {
	return map[string]func(*Session) error{
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
}

func TestSession_AppliesTheTimeoutAsARealDuration(t *testing.T) {
	const timeout = 2 * time.Second

	for name, call := range sessionCalls(timeout) {
		t.Run(name, func(t *testing.T) {
			rec := &deadlineRecorder{}
			session := &Session{BaseURL: "http://alpacon.test", Client: &http.Client{Transport: rec}}
			start := time.Now()

			err := call(session)
			end := time.Now()

			require.NoError(t, err)
			require.True(t, rec.ok, "the request carries a deadline")
			assert.WithinRange(t, rec.deadline, start.Add(timeout), end.Add(timeout))
		})
	}
}

func TestSession_RejectsABareIntegerTimeoutWithoutSending(t *testing.T) {
	for name, call := range sessionCalls(10) {
		t.Run(name, func(t *testing.T) {
			rec := &deadlineRecorder{}
			session := &Session{BaseURL: "http://alpacon.test", Client: &http.Client{Transport: rec}}

			err := call(session)

			assert.ErrorContains(t, err, "request timeout 10ns is too short")
			assert.False(t, rec.called, "nothing is sent")
		})
	}
}
