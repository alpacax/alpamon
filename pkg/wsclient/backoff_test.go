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
		max:     600 * time.Millisecond,
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
		400 * time.Millisecond, // held at two thirds of max from here on
		400 * time.Millisecond,
		400 * time.Millisecond,
	}, base, "the base must keep doubling to the ceiling whatever the jitter draws")

	assert.Equal(t, []time.Duration{
		125 * time.Millisecond,
		250 * time.Millisecond,
		500 * time.Millisecond, // 1.25x of the 400ms ceiling, still under max
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
		max:     600 * time.Millisecond,
		rand:    func() float64 { return 0 },
	}
	assert.Equal(t, 100*time.Millisecond, low.next(), "the lowest draw returns the base itself, the floor")

	high := &backoff{
		initial: 100 * time.Millisecond,
		max:     600 * time.Millisecond,
		rand:    func() float64 { return 0.999999 },
	}
	for range 5 {
		high.next()
	}
	// The top of the ceiling's window reaches nearly max without touching it,
	// which is what stopping the base at two thirds buys.
	top := high.next()
	assert.Less(t, top, 600*time.Millisecond)
	assert.Greater(t, top, 599*time.Millisecond)
}

// TestBackoff_JittersAtTheCeiling is the regression for a schedule that goes
// flat exactly where the jitter matters most. A base of max puts every draw
// at or above max, the clamp returns max for all of them, and a fleet that
// has been retrying long enough to reach the ceiling redials on one tick --
// which is the state a backhaul restart finds it in.
func TestBackoff_JittersAtTheCeiling(t *testing.T) {
	b := &backoff{initial: 5 * time.Second, max: time.Minute}
	for range 6 {
		b.next() // well past the ceiling
	}

	seen := map[time.Duration]bool{}
	for range 50 {
		d := b.next()
		assert.GreaterOrEqual(t, d, 40*time.Second, "the ceiling's window starts at two thirds of max")
		assert.Less(t, d, time.Minute, "and stays under max")
		seen[d] = true
	}
	assert.Greater(t, len(seen), 45, "waits at the ceiling must not collapse onto one value")
}

// TestBackoff_JittersWithAFloorNearTheCeiling covers the one base the two
// thirds rule cannot lower. initial is the floor, so a MinBackoff set above
// two thirds of MaxBackoff leaves the base sitting there with less room than
// a window of half again needs. Multiplying past max and clamping back put
// 60% of those draws on max itself, at initial 50s and max 60s; drawing
// across the room that is actually there keeps them apart.
func TestBackoff_JittersWithAFloorNearTheCeiling(t *testing.T) {
	b := &backoff{initial: 50 * time.Second, max: time.Minute}
	for range 3 {
		b.next() // the base is pinned at initial from the first call on
	}

	seen := map[time.Duration]bool{}
	for range 200 {
		d := b.next()
		assert.GreaterOrEqual(t, d, 50*time.Second, "MinBackoff is still the floor")
		assert.Less(t, d, time.Minute, "and MaxBackoff still the bound")
		seen[d] = true
	}
	assert.Greater(t, len(seen), 190, "a floor this close to the ceiling still has room to spread across")
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
	assert.Equal(t, time.Duration(math.MaxInt64)/3*2, b.current, "the base must settle on the ceiling, not wrap")
}

func TestBackoff_ResetRestartsTheSequence(t *testing.T) {
	b := &backoff{
		initial: 100 * time.Millisecond,
		max:     600 * time.Millisecond,
		rand:    func() float64 { return 0 }, // factor 1.0, isolates reset from jitter
	}

	for range 4 {
		b.next()
	}
	require.Equal(t, 400*time.Millisecond, b.current, "the sequence should have reached the ceiling")

	b.reset()
	assert.Equal(t, 100*time.Millisecond, b.next(), "the first wait after reset starts over at the floor")
}
