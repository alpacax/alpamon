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
//
// Spreading upward is also why the base stops short of max rather than at
// it. A base of max would put every draw at or above max, the clamp would
// return max for all of them, and the schedule would go flat exactly where
// the jitter matters most: a fleet that has been retrying long enough to
// reach the ceiling is a fleet already in step. The base stops at two thirds
// of max instead, which is the largest one whose whole window still fits
// underneath, so the ceiling is a spread over [2/3 max, max) rather than a
// single instant. A configuration with initial equal to max has no room for
// any of this and gets that one value, which is what it asked for.
func (b *backoff) next() time.Duration {
	ceiling := b.max / 3 * 2 // divide first: b.max*2 can overflow
	if ceiling < b.initial {
		ceiling = b.initial
	}
	switch {
	case b.current == 0:
		b.current = b.initial
	case b.current > ceiling/2: // doubling would pass the ceiling, or overflow
		b.current = ceiling
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
	return max(time.Duration(jittered), b.initial)
}

// reset is called for a connection that worked, so the next failure starts
// the schedule over rather than resuming where the last outage left it.
func (b *backoff) reset() {
	b.current = 0
}
