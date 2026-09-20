package runner

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/gorilla/websocket"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func rejection(status int) error {
	return &handshakeError{StatusCode: status, Err: websocket.ErrBadHandshake}
}

// newTestBackoff returns a backoff on a clock the caller advances and with
// every jitter draw fixed at the midpoint, so an interval asserts exactly.
func newTestBackoff(clock *time.Time) *authBackoff {
	a := newAuthBackoff(minConnectInterval, maxConnectInterval)
	a.now = func() time.Time { return *clock }
	a.rand = func() float64 { return 0.5 }
	a.backoff.Rand = func() float64 { return 0.5 }
	return a
}

// attempt is one failed connection attempt, or a successful one when err is
// nil, made advance after the previous one.
type attempt struct {
	advance time.Duration
	err     error
}

func TestAuthBackoff_Escalation(t *testing.T) {
	refused := errors.New("dial tcp 10.0.0.1:443: connect: connection refused")

	tests := []struct {
		name string
		// attempts are played in order against the same backoff.
		attempts []attempt
		// wantEscalatedAt is the index of the attempt that crosses the
		// threshold, or -1 when the backoff never escalates.
		wantEscalatedAt int
		// wantEscalated is the state left at the end, which differs from
		// wantEscalatedAt >= 0 once a successful connection has cleared it.
		wantEscalated bool
		wantCount     int
	}{
		{
			name: "rejections over the whole span escalate on the one that crosses it",
			attempts: []attempt{
				{err: rejection(http.StatusUnauthorized)},
				{advance: 10 * time.Minute, err: rejection(http.StatusUnauthorized)},
				{advance: 10 * time.Minute, err: rejection(http.StatusUnauthorized)},
				{advance: 10 * time.Minute, err: rejection(http.StatusUnauthorized)},
				{advance: 10 * time.Minute, err: rejection(http.StatusUnauthorized)},
			},
			wantEscalatedAt: 4,
			wantEscalated:   true,
			wantCount:       5,
		},
		{
			name: "403 and 404 are rejections too",
			attempts: []attempt{
				{err: rejection(http.StatusNotFound)},
				{advance: 15 * time.Minute, err: rejection(http.StatusForbidden)},
				{advance: 15 * time.Minute, err: rejection(http.StatusNotFound)},
				{err: rejection(http.StatusForbidden)},
				{err: rejection(http.StatusUnauthorized)},
			},
			wantEscalatedAt: 4,
			wantEscalated:   true,
			wantCount:       5,
		},
		{
			name: "a burst of rejections inside the span does not escalate",
			attempts: []attempt{
				{err: rejection(http.StatusUnauthorized)},
				{advance: 5 * time.Second, err: rejection(http.StatusUnauthorized)},
				{advance: 10 * time.Second, err: rejection(http.StatusUnauthorized)},
				{advance: 20 * time.Second, err: rejection(http.StatusUnauthorized)},
				{advance: 40 * time.Second, err: rejection(http.StatusUnauthorized)},
				{advance: time.Minute, err: rejection(http.StatusUnauthorized)},
				{advance: time.Minute, err: rejection(http.StatusUnauthorized)},
			},
			wantEscalatedAt: -1,
			wantCount:       7,
		},
		{
			name: "too few rejections do not escalate however long they take",
			attempts: []attempt{
				{err: rejection(http.StatusUnauthorized)},
				{advance: time.Hour, err: rejection(http.StatusUnauthorized)},
				{advance: time.Hour, err: rejection(http.StatusUnauthorized)},
				{advance: time.Hour, err: rejection(http.StatusUnauthorized)},
			},
			wantEscalatedAt: -1,
			wantCount:       4,
		},
		{
			name: "transport errors and 5xx never escalate on their own",
			attempts: []attempt{
				{err: refused},
				{advance: 30 * time.Minute, err: refused},
				{advance: 30 * time.Minute, err: rejection(http.StatusInternalServerError)},
				{advance: 30 * time.Minute, err: rejection(http.StatusServiceUnavailable)},
				{advance: 30 * time.Minute, err: rejection(http.StatusBadGateway)},
				{advance: 30 * time.Minute, err: refused},
			},
			wantEscalatedAt: -1,
			wantCount:       0,
		},
		{
			name: "a transport error between rejections neither counts nor clears",
			attempts: []attempt{
				{err: rejection(http.StatusUnauthorized)},
				{advance: 10 * time.Minute, err: refused},
				{advance: 10 * time.Minute, err: rejection(http.StatusUnauthorized)},
				{advance: 10 * time.Minute, err: rejection(http.StatusServiceUnavailable)},
				{advance: 5 * time.Minute, err: rejection(http.StatusUnauthorized)},
				{advance: 5 * time.Minute, err: rejection(http.StatusUnauthorized)},
				{advance: 5 * time.Minute, err: rejection(http.StatusUnauthorized)},
			},
			wantEscalatedAt: 6,
			wantEscalated:   true,
			wantCount:       5,
		},
		{
			name: "a connection that comes up clears an established streak",
			attempts: []attempt{
				{err: rejection(http.StatusUnauthorized)},
				{advance: 10 * time.Minute, err: rejection(http.StatusUnauthorized)},
				{advance: 10 * time.Minute, err: rejection(http.StatusUnauthorized)},
				{advance: 10 * time.Minute, err: rejection(http.StatusUnauthorized)},
				{advance: 10 * time.Minute, err: rejection(http.StatusUnauthorized)},
				{advance: time.Hour},
				{advance: time.Minute, err: rejection(http.StatusUnauthorized)},
				{advance: time.Hour, err: rejection(http.StatusUnauthorized)},
			},
			wantEscalatedAt: 4,
			wantEscalated:   false,
			wantCount:       2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clock := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
			a := newTestBackoff(&clock)

			escalatedAt := -1
			for i, step := range tt.attempts {
				clock = clock.Add(step.advance)

				if step.err == nil {
					a.success()
					assert.False(t, a.escalated, "attempt %d: a successful connection leaves the backoff escalated", i)
					assert.Zero(t, a.count, "attempt %d: a successful connection leaves rejections counted", i)
					continue
				}

				wait, escalated := a.next(step.err)
				if escalated {
					require.Equal(t, -1, escalatedAt, "attempt %d: escalated a second time, so the warning would repeat", i)
					escalatedAt = i
				}

				if a.escalated {
					assert.Equal(t, authRejectedInterval, wait, "attempt %d: not waiting the long interval", i)
				} else {
					assert.LessOrEqual(t, wait, maxConnectInterval, "attempt %d: waiting longer than the ordinary backoff", i)
				}
			}

			assert.Equal(t, tt.wantEscalatedAt, escalatedAt)
			assert.Equal(t, tt.wantEscalated, a.escalated)
			assert.Equal(t, tt.wantCount, a.count)
		})
	}
}

func TestAuthBackoff_LongIntervalJitterBounds(t *testing.T) {
	tests := []struct {
		name string
		draw float64
		want time.Duration
	}{
		{name: "lowest draw", draw: 0, want: authRejectedInterval / 2},
		{name: "midpoint draw", draw: 0.5, want: authRejectedInterval},
		{name: "highest draw", draw: 0.999999, want: 3 * authRejectedInterval / 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := newAuthBackoff(minConnectInterval, maxConnectInterval)
			a.rand = func() float64 { return tt.draw }

			got := a.longInterval()
			assert.GreaterOrEqual(t, got, authRejectedInterval/2)
			assert.Less(t, got, 3*authRejectedInterval/2+time.Second)
			assert.InDelta(t, tt.want, got, float64(time.Second))
		})
	}
}

func TestIsAuthRejection_UnwrapsAndIgnoresOtherErrors(t *testing.T) {
	assert.True(t, isAuthRejection(fmt.Errorf("connect: %w", rejection(http.StatusUnauthorized))),
		"a wrapped rejection is still a rejection")
	assert.False(t, isAuthRejection(errors.New("connection refused")))
	assert.False(t, isAuthRejection(websocket.ErrBadHandshake),
		"a handshake error with no status cannot be read as a rejection")
	assert.False(t, isAuthRejection(nil))
}

func TestDialWebsocket_SurfacesHandshakeStatus(t *testing.T) {
	tests := []struct {
		name          string
		status        int
		wantRejection bool
	}{
		{name: "unauthorized", status: http.StatusUnauthorized, wantRejection: true},
		{name: "forbidden", status: http.StatusForbidden, wantRejection: true},
		{name: "not found", status: http.StatusNotFound, wantRejection: true},
		{name: "service unavailable", status: http.StatusServiceUnavailable, wantRejection: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tt.status)
			}))
			defer server.Close()

			conn, err := dialWebsocket(t.Context(), wsURL(server.URL), nil)
			require.Error(t, err)
			assert.Nil(t, conn)
			require.ErrorIs(t, err, websocket.ErrBadHandshake)

			var handshake *handshakeError
			require.ErrorAs(t, err, &handshake)
			assert.Equal(t, tt.status, handshake.StatusCode)
			assert.ErrorContains(t, err, fmt.Sprintf("HTTP %d", tt.status))
			assert.Equal(t, tt.wantRejection, isAuthRejection(err))
		})
	}

	t.Run("no handshake at all", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
		url := wsURL(server.URL)
		server.Close()

		conn, err := dialWebsocket(t.Context(), url, nil)
		require.Error(t, err)
		assert.Nil(t, conn)

		var handshake *handshakeError
		assert.False(t, errors.As(err, &handshake), "a server that never answered has no status to report")
		assert.False(t, isAuthRejection(err))
	})

	t.Run("a cancelled context stops the dial", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
		defer server.Close()

		ctx, cancel := context.WithCancel(t.Context())
		cancel()

		conn, err := dialWebsocket(ctx, wsURL(server.URL), nil)
		require.ErrorIs(t, err, context.Canceled, "the dial does not observe the caller's context")
		assert.Nil(t, conn)
	})
}

func wsURL(httpURL string) string {
	return "ws" + strings.TrimPrefix(httpURL, "http")
}

func TestConnectForever_SlowsToTheLongIntervalAfterRepeatedRejections(t *testing.T) {
	logs := captureLogs(t)

	const attempts = 40
	var at []time.Duration
	var a *authBackoff

	synctest.Test(t, func(t *testing.T) {
		clock := time.Now()
		a = newAuthBackoff(minConnectInterval, maxConnectInterval)
		a.rand = func() float64 { return 0.5 }
		a.backoff.Rand = func() float64 { return 0.5 }

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		err := connectForever(ctx, a, "wss://alpacon.example/ws/", func() error {
			at = append(at, time.Since(clock))
			if len(at) == attempts {
				cancel()
			}
			return rejection(http.StatusUnauthorized)
		})

		require.ErrorIs(t, err, context.Canceled, "the loop stops only when the context ends")
	})

	require.Len(t, at, attempts, "the loop gave up before the context ended")
	require.True(t, a.escalated)

	escalatedAt := -1
	for i := 1; i < len(at); i++ {
		gap := at[i] - at[i-1]
		if escalatedAt < 0 && gap > maxConnectInterval {
			escalatedAt = i - 1
		}
		if escalatedAt < 0 {
			assert.LessOrEqual(t, gap, maxConnectInterval, "attempt %d came after more than the ordinary backoff", i)
		} else {
			assert.Equal(t, authRejectedInterval, gap, "attempt %d did not wait the long interval", i)
		}
	}

	require.GreaterOrEqual(t, escalatedAt, 0, "the loop never slowed down")
	assert.GreaterOrEqual(t, at[escalatedAt], authRejectionSpan, "slowed down before the streak spanned %s", authRejectionSpan)
	assert.GreaterOrEqual(t, escalatedAt+1, authRejectionThreshold, "slowed down after fewer than %d rejections", authRejectionThreshold)

	assert.Equal(t, 1, strings.Count(logs.String(), "rejected this agent's credentials"),
		"the warning is logged once per streak, not on every attempt")
}

// captureLogs redirects the global logger into a buffer for the duration of
// the test, so a test can assert on what was logged and how often.
func captureLogs(t *testing.T) *bytes.Buffer {
	t.Helper()

	previousLogger, previousLevel := log.Logger, zerolog.GlobalLevel()
	t.Cleanup(func() {
		log.Logger = previousLogger
		zerolog.SetGlobalLevel(previousLevel)
	})

	var buf bytes.Buffer
	log.Logger = zerolog.New(&buf)
	zerolog.SetGlobalLevel(zerolog.InfoLevel)

	return &buf
}
