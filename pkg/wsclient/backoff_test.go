package wsclient

import (
	"math"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The cases below mirror internal/retry/retry_test.go, which pins the same
// schedule. Keep the two in step.

// TestBackoff_BaseDoublingReachesCeiling pins the draw to a non-neutral
// factor (1.25x) and asserts on the internal base apart from the returned
// value. At the neutral factor (1.0x) an implementation that feeds the
// jittered value back into the base produces the same numbers as a correct
// one, so only a non-neutral factor tells them apart.
func TestBackoff_BaseDoublingReachesCeiling(t *testing.T) {
	b := &backoff{
		initial: 100 * time.Millisecond,
		max:     500 * time.Millisecond,
		rand:    func() float64 { return 0.5 }, // factor 1.25
	}

	returned := make([]time.Duration, 6)
	base := make([]time.Duration, 6)
	for i := range returned {
		returned[i] = b.next()
		base[i] = b.current
	}

	assert.Equal(t, []time.Duration{
		100 * time.Millisecond,
		200 * time.Millisecond,
		400 * time.Millisecond,
		500 * time.Millisecond, // capped at max from here on
		500 * time.Millisecond,
		500 * time.Millisecond,
	}, base, "the base must keep doubling to the ceiling whatever the jitter draws")

	assert.Equal(t, []time.Duration{
		125 * time.Millisecond,
		250 * time.Millisecond,
		500 * time.Millisecond, // 1.25x of 400ms, clamped down to the ceiling
		500 * time.Millisecond,
		500 * time.Millisecond,
		500 * time.Millisecond,
	}, returned)
}

// TestBackoff_JitterStaysInBounds draws from the real source across the whole
// doubling sequence and checks every wait lands in [initial, max].
func TestBackoff_JitterStaysInBounds(t *testing.T) {
	const (
		initial = 100 * time.Millisecond
		maxWait = 500 * time.Millisecond
	)

	for range 500 {
		b := &backoff{initial: initial, max: maxWait}
		for range 10 {
			d := b.next()
			assert.GreaterOrEqual(t, d, initial)
			assert.LessOrEqual(t, d, maxWait)
		}
	}
}

// TestBackoff_JitterVariesTheWait guards against a jitter that silently does
// nothing, such as a draw whose result is discarded.
func TestBackoff_JitterVariesTheWait(t *testing.T) {
	seen := map[time.Duration]bool{}
	for range 200 {
		b := &backoff{initial: 100 * time.Millisecond, max: 10 * time.Second}
		seen[b.next()] = true
	}

	assert.Greater(t, len(seen), 1, "200 first draws should not all land on one value")
}

func TestBackoff_ExtremeDrawsClamp(t *testing.T) {
	low := &backoff{
		initial: 100 * time.Millisecond,
		max:     500 * time.Millisecond,
		rand:    func() float64 { return 0 },
	}
	assert.Equal(t, 100*time.Millisecond, low.next(), "the lowest draw returns the base itself, the floor")

	high := &backoff{
		initial: 100 * time.Millisecond,
		max:     500 * time.Millisecond,
		rand:    func() float64 { return 0.999999 },
	}
	for range 5 {
		high.next()
	}
	assert.Equal(t, 500*time.Millisecond, high.next(), "~1.5x of the ceiling clamps down to it")
}

// TestBackoff_HostileDrawsClamp covers a caller-supplied source that breaks
// its [0, 1) contract. The clamp has to hold for these too, since a wait of
// zero or less would turn the reconnect loop into a busy loop.
func TestBackoff_HostileDrawsClamp(t *testing.T) {
	for name, draw := range map[string]float64{
		"negative": -5,
		"too big":  7,
		"NaN":      math.NaN(),
		"infinity": math.Inf(1),
	} {
		t.Run(name, func(t *testing.T) {
			b := &backoff{
				initial: 100 * time.Millisecond,
				max:     500 * time.Millisecond,
				rand:    func() float64 { return draw },
			}
			for range 6 {
				d := b.next()
				assert.GreaterOrEqual(t, d, 100*time.Millisecond)
				assert.LessOrEqual(t, d, 500*time.Millisecond)
			}
		})
	}
}

// TestBackoff_LargeMaxDoesNotOverflow drives the base against a ceiling near
// the top of time.Duration, where a naive doubling or a 1.5x factor would wrap
// negative.
func TestBackoff_LargeMaxDoesNotOverflow(t *testing.T) {
	b := &backoff{
		initial: time.Second,
		max:     time.Duration(math.MaxInt64),
		rand:    func() float64 { return 0.999999 },
	}
	for range 80 {
		d := b.next()
		require.Positive(t, d)
		require.Positive(t, b.current)
	}
	assert.Equal(t, time.Duration(math.MaxInt64), b.current, "the base must settle on the ceiling, not wrap")
}

func TestBackoff_ResetRestartsTheSequence(t *testing.T) {
	b := &backoff{
		initial: 100 * time.Millisecond,
		max:     500 * time.Millisecond,
		rand:    func() float64 { return 0 }, // factor 1.0, isolates reset from jitter
	}

	for range 4 {
		b.next()
	}
	require.Equal(t, 500*time.Millisecond, b.current, "the sequence should have reached the ceiling")

	b.reset()
	assert.Equal(t, 100*time.Millisecond, b.next(), "the first wait after reset starts over at the floor")
}
