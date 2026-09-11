package wsclient

import (
	"context"
	"errors"
	"net"
	"testing"
	"testing/synctest"
	"time"

	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// These tests time the reconnect schedule under synctest's fake clock. That
// only works because no socket is involved: the dialer fails in-process, so
// the one thing Run ever blocks on is its backoff timer, which the bubble
// counts as blocked and fast-forwards.

var errRefused = errors.New("connection refused")

// refusingConfig returns a config whose every dial fails at once, without
// touching the network. Proxy stays nil so no dial step reads the environment.
func refusingConfig() Config {
	cfg := validConfig()
	cfg.Dialer = &websocket.Dialer{
		NetDialContext: func(context.Context, string, string) (net.Conn, error) {
			return nil, errRefused
		},
	}
	return cfg
}

// TestRun_BackoffScheduleUnderAFakeClock checks both the waits Run reports and
// when each retry actually happens. With the draw pinned to 0 the factor is
// 1.0, so each wait is the base itself: 1s, 2s, 4s, then 8s from the ceiling
// on.
func TestRun_BackoffScheduleUnderAFakeClock(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		start := time.Now()

		var attempts []int
		var waits, at []time.Duration
		cfg := refusingConfig()
		cfg.MinBackoff = time.Second
		cfg.MaxBackoff = 8 * time.Second
		cfg.Rand = func() float64 { return 0 }
		cfg.OnRetry = func(attempt int, delay time.Duration, err error) {
			assert.ErrorIs(t, err, errRefused)
			attempts = append(attempts, attempt)
			waits = append(waits, delay)
			at = append(at, time.Since(start))
			if attempt == 6 {
				cancel() // lands before Run waits out the sixth delay
			}
		}
		c, err := New(cfg)
		require.NoError(t, err)

		require.ErrorIs(t, c.Run(ctx, discard), context.Canceled)

		assert.Equal(t, []int{1, 2, 3, 4, 5, 6}, attempts)
		assert.Equal(t, []time.Duration{
			time.Second,
			2 * time.Second,
			4 * time.Second,
			8 * time.Second, // the base is capped at 8s from here on
			8 * time.Second,
			8 * time.Second,
		}, waits)
		// Each retry fires exactly when the previous wait ends: the bubble's
		// clock is exact, so these would catch a wait that ran long or short.
		assert.Equal(t, []time.Duration{
			0,
			time.Second,
			3 * time.Second,
			7 * time.Second,
			15 * time.Second,
			23 * time.Second,
		}, at)
		assert.Equal(t, 23*time.Second, time.Since(start), "cancelling during a retry must not wait out its delay")
	})
}

func TestRun_ShutdownDuringBackoffReturnsAtOnce(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		retried := make(chan struct{}, 1)
		cfg := refusingConfig()
		cfg.MinBackoff = time.Minute
		cfg.MaxBackoff = time.Hour
		cfg.OnRetry = func(int, time.Duration, error) { retried <- struct{}{} }
		c, err := New(cfg)
		require.NoError(t, err)

		start := time.Now()
		result := make(chan error, 1)
		go func() { result <- c.Run(t.Context(), discard) }()

		<-retried
		synctest.Wait() // Run is now parked on its first backoff timer
		c.Shutdown()

		require.NoError(t, <-result)
		assert.Zero(t, time.Since(start), "Shutdown must cut the backoff wait short, not wait out the minute")
	})
}

// TestRun_JitterDesynchronizesClients is the point of the jitter: clients
// that lose the backhaul at the same instant must not retry in lockstep. It
// samples the very first wait, which is the one that matters after a fleet-
// wide drop, and which a factor range starting below 1.0 would collapse onto
// the floor for half the fleet.
//
// It reads that wait off the second retry rather than the first, because
// OnRetry announces a wait before serving it: the clock when attempt 2 is
// announced is exactly how long attempt 1's wait ran. Sampling the delay
// attempt 1 reports would be the obvious spelling and a weaker test, proving
// only what was announced rather than what the client waited.
func TestRun_JitterDesynchronizesClients(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const clients = 50
		firstRetry := make(chan time.Duration, clients)
		start := time.Now()
		ctx, cancel := context.WithCancel(t.Context())

		for range clients {
			cfg := refusingConfig()
			cfg.MinBackoff = time.Second
			cfg.MaxBackoff = time.Minute
			cfg.OnRetry = func(attempt int, _ time.Duration, _ error) {
				if attempt == 2 {
					firstRetry <- time.Since(start)
				}
			}
			c, err := New(cfg)
			require.NoError(t, err)
			go func() { _ = c.Run(ctx, discard) }()
		}

		seen := map[time.Duration]bool{}
		earliest, latest := time.Duration(1<<63-1), time.Duration(0)
		for range clients {
			d := <-firstRetry
			seen[d] = true
			earliest, latest = min(earliest, d), max(latest, d)
		}
		cancel()

		assert.Greater(t, len(seen), clients*9/10, "clients should retry at distinct instants")
		assert.GreaterOrEqual(t, earliest, time.Second, "no wait may undercut MinBackoff")
		assert.GreaterOrEqual(t, latest-earliest, 300*time.Millisecond, "the first retries should spread across the jitter window")
	})
}
