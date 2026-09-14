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

// next returns the next wait, drawn uniformly from the doubling base up to
// half again as much, and clamped to [initial, max]. Without the draw every
// agent reconnecting after the same event, such as a backhaul restart, would
// retry in lockstep.
//
// The window opens upward from the base rather than around it, which is
// where internal/retry puts it, because a window reaching below the base
// would be swallowed by the clamp at the first attempt: the base is initial
// there, so every draw under it returns exactly initial and half a fleet
// retries on the same tick. Opening upward keeps initial a real floor and
// the spread intact.
//
// Opening upward is also why the base stops short of max rather than at it.
// A base of max would put the whole window at or above max and the schedule
// would go flat exactly where the spread matters most: a fleet that has been
// retrying long enough to reach the ceiling is a fleet already in step. The
// base stops at two thirds of max instead, the largest one whose whole
// window still fits underneath, so the ceiling is a spread over [2/3 max,
// max) rather than a single instant. A configuration with initial equal to
// max has no room for any of this and gets that one value, which is what it
// asked for.
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

	// Draw across the window the base actually has rather than multiplying
	// past max and clamping back. They agree wherever the whole window fits,
	// and where it does not they do not: initial is the one base the ceiling
	// cannot lower, so a MinBackoff above two thirds of MaxBackoff leaves
	// most of the multiplied draws sitting on max itself. Measured at
	// initial 50s and max 60s, that is 60% of them.
	top := b.max
	if b.current <= b.max-b.current/2 { // else half again would pass max
		top = b.current + b.current/2
	}
	// In float64 before converting: the sum can pass time.Duration on a
	// large max, and !(x < max) also catches a NaN from a caller's source.
	jittered := float64(b.current) + float64(top-b.current)*randFn()
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
