package wsclient

import (
	"math/rand/v2"
	"time"
)

// backoff is the reconnect schedule: exponential with jitter. It mirrors
// internal/retry.ExponentialBackoff rather than importing it, because Go's
// internal rule keeps internal/ out of reach of the modules this package
// exists for.
//
// The base doubles from initial up to max, and only the value handed back is
// jittered. Keeping the base pure means an unlucky draw never drags the
// sequence down, so it reaches max on the same schedule every time.
type backoff struct {
	initial time.Duration
	max     time.Duration
	rand    func() float64 // returns [0, 1); nil means math/rand/v2

	current time.Duration
}

// next returns the next wait: the doubling base multiplied by a factor in
// [1.0, 1.5), clamped to [initial, max]. Without the random factor every
// agent reconnecting after the same event, such as a backhaul restart, would
// retry in lockstep.
//
// The factor starts at 1.0 rather than 0.5, which is where internal/retry
// starts it, because the clamp to initial would otherwise swallow the whole
// lower half: at the first attempt the base is initial, so every draw below
// 1.0 returns exactly initial and half of a fleet retries on the same tick.
// Spreading upward keeps initial a real floor and the distribution intact.
func (b *backoff) next() time.Duration {
	switch {
	case b.current == 0:
		b.current = b.initial
	case b.current > b.max/2: // doubling would pass max, or overflow
		b.current = b.max
	default:
		b.current *= 2
	}

	randFn := b.rand
	if randFn == nil {
		randFn = rand.Float64
	}

	// Clamp in float64 before converting: a factor near 1.5 on a large max
	// would overflow time.Duration, and !(x < max) also catches a NaN from
	// a caller-supplied source.
	jittered := float64(b.current) * (1.0 + 0.5*randFn())
	if !(jittered < float64(b.max)) {
		return b.max
	}
	if d := time.Duration(jittered); d > b.initial {
		return d
	}
	return b.initial
}

// reset restarts the schedule at initial, after a connection succeeds.
func (b *backoff) reset() {
	b.current = 0
}
