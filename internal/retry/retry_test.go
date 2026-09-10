package retry

import (
	"context"
	"errors"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRetry_Success(t *testing.T) {
	b := &ExponentialBackoff{
		InitialInterval: 10 * time.Millisecond,
		MaxInterval:     100 * time.Millisecond,
	}

	calls := 0
	err := Retry(context.Background(), b, func() error {
		calls++
		if calls < 3 {
			return errors.New("not yet")
		}
		return nil
	})

	require.NoError(t, err)
	assert.Equal(t, 3, calls)
}

func TestRetry_PermanentError(t *testing.T) {
	b := &ExponentialBackoff{
		InitialInterval: 10 * time.Millisecond,
		MaxInterval:     100 * time.Millisecond,
	}

	fatal := errors.New("fatal error")
	calls := 0
	err := Retry(context.Background(), b, func() error {
		calls++
		return Permanent(fatal)
	})

	require.ErrorIs(t, err, fatal)
	assert.Equal(t, 1, calls, "no retry after a permanent error")
}

func TestRetry_ContextCancellation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())

		b := &ExponentialBackoff{
			InitialInterval: 1 * time.Second,
			MaxInterval:     1 * time.Second,
		}

		calls := 0
		go func() {
			// Cancel once Retry is parked on its backoff timer, not mid-operation.
			synctest.Wait()
			cancel()
		}()

		err := Retry(ctx, b, func() error {
			calls++
			return errors.New("keep trying")
		})

		require.ErrorIs(t, err, context.Canceled)
		// The cancel always lands after exactly one call; a ">=" would also pass for a loop that kept retrying past it.
		assert.Equal(t, 1, calls, "the cancel lands on the first backoff, so exactly one call")
	})
}

func TestRetry_MaxElapsedTime(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		b := &ExponentialBackoff{
			InitialInterval: 10 * time.Millisecond,
			MaxInterval:     10 * time.Millisecond,
			MaxElapsedTime:  50 * time.Millisecond,
		}

		start := time.Now()
		err := Retry(context.Background(), b, func() error {
			return errors.New("always fail")
		})

		require.Error(t, err, "expected error after max elapsed time")
		// The bubble's clock is exact, so a ">=" would also pass for a loop that overran MaxElapsedTime.
		assert.Equal(t, 50*time.Millisecond, time.Since(start), "the give-up must land on MaxElapsedTime")
	})
}

// TestNextBackOff_BaseDoublingReachesCeiling pins Rand to always return 0.5,
// which yields a jitter factor of exactly 1.0 (no-op), so the underlying
// doubling sequence is observable directly: 100ms, 200ms, 400ms, capped at
// 500ms from there on. This is what "the doubling of the base interval is
// unaffected by the random draw" buys: the ceiling is still reached exactly
// on schedule even though real draws jitter the returned value.
func TestNextBackOff_BaseDoublingReachesCeiling(t *testing.T) {
	b := &ExponentialBackoff{
		InitialInterval: 100 * time.Millisecond,
		MaxInterval:     500 * time.Millisecond,
		Rand:            func() float64 { return 0.5 },
	}

	intervals := make([]time.Duration, 6)
	for i := range intervals {
		intervals[i] = b.NextBackOff()
	}

	assert.Equal(t, 100*time.Millisecond, intervals[0])
	assert.Equal(t, 200*time.Millisecond, intervals[1])
	assert.Equal(t, 400*time.Millisecond, intervals[2])
	assert.Equal(t, 500*time.Millisecond, intervals[3], "capped at max from here on")
	assert.Equal(t, 500*time.Millisecond, intervals[4])
	assert.Equal(t, 500*time.Millisecond, intervals[5])
}

// TestNextBackOff_JitterBounds draws many samples across the whole
// InitialInterval..MaxInterval doubling sequence (using the real default
// Rand, not a stub) and checks every one lands in [InitialInterval,
// MaxInterval] — the clamp that keeps a 0.5x draw from undercutting the
// configured floor and a 1.49x draw from overshooting the ceiling.
func TestNextBackOff_JitterBounds(t *testing.T) {
	const (
		initial = 100 * time.Millisecond
		maxIvl  = 500 * time.Millisecond
	)

	for range 500 {
		b := &ExponentialBackoff{InitialInterval: initial, MaxInterval: maxIvl}

		for range 10 {
			d := b.NextBackOff()
			assert.GreaterOrEqual(t, d, initial)
			assert.LessOrEqual(t, d, maxIvl)
		}
	}
}

// TestNextBackOff_JitterVariesTheReturnedValue guards against a jitter
// implementation that silently no-ops (e.g. a Rand call whose result is
// discarded): repeated draws at a fixed base interval must not all come back
// identical.
func TestNextBackOff_JitterVariesTheReturnedValue(t *testing.T) {
	seen := map[time.Duration]bool{}
	for range 200 {
		b := &ExponentialBackoff{
			InitialInterval: 100 * time.Millisecond,
			MaxInterval:     10 * time.Second, // high enough that the clamp doesn't hide the spread
		}
		seen[b.NextBackOff()] = true
	}

	assert.Greater(t, len(seen), 1, "200 draws at the same base interval should not all collapse to one value")
}

// TestNextBackOff_ExtremeDraws checks the two edges of the jitter factor
// directly: a draw of 0 (factor 0.5) must clamp up to InitialInterval when
// the base is at InitialInterval, and a draw just under 1 (factor just under
// 1.5) must clamp down to MaxInterval when the base is at MaxInterval.
func TestNextBackOff_ExtremeDraws(t *testing.T) {
	low := &ExponentialBackoff{
		InitialInterval: 100 * time.Millisecond,
		MaxInterval:     500 * time.Millisecond,
		Rand:            func() float64 { return 0 },
	}
	assert.Equal(t, 100*time.Millisecond, low.NextBackOff(), "0.5x of the initial interval clamps up to the floor")

	high := &ExponentialBackoff{
		InitialInterval: 100 * time.Millisecond,
		MaxInterval:     500 * time.Millisecond,
		Rand:            func() float64 { return 0.999999 },
	}
	// Drive the base up to the ceiling first.
	for range 5 {
		high.NextBackOff()
	}
	assert.Equal(t, 500*time.Millisecond, high.NextBackOff(), "~1.5x of the max interval clamps down to the ceiling")
}

// TestNextBackOff_ResetRestartsTheSequence confirms Reset drops the internal
// base back to zero so the next call starts the doubling sequence over,
// exactly as it did before jitter was added.
func TestNextBackOff_ResetRestartsTheSequence(t *testing.T) {
	b := &ExponentialBackoff{
		InitialInterval: 100 * time.Millisecond,
		MaxInterval:     500 * time.Millisecond,
		Rand:            func() float64 { return 0.5 }, // factor 1.0, isolates the reset behavior from jitter
	}

	for range 4 {
		b.NextBackOff()
	}
	require.Equal(t, 500*time.Millisecond, b.currentInterval, "sequence should have reached the ceiling")

	b.Reset()
	assert.Equal(t, time.Duration(0), b.currentInterval)
	assert.Equal(t, 100*time.Millisecond, b.NextBackOff(), "first call after Reset restarts at InitialInterval")
}

func TestRetry_ImmediateSuccess(t *testing.T) {
	b := &ExponentialBackoff{
		InitialInterval: 1 * time.Second,
		MaxInterval:     1 * time.Second,
	}

	err := Retry(context.Background(), b, func() error {
		return nil
	})

	if err != nil {
		t.Fatalf("expected nil, got %v", err)
	}
}

func TestPermanentError_Unwrap(t *testing.T) {
	inner := errors.New("inner")
	pe := Permanent(inner)

	var permanent *PermanentError
	if !errors.As(pe, &permanent) {
		t.Fatal("expected errors.As to match PermanentError")
	}
	if !errors.Is(pe, inner) {
		t.Fatal("expected errors.Is to find inner error")
	}
}
