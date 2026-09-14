package retry

import (
	"context"
	"errors"
	"math"
	"math/rand/v2"
	"time"
)

// PermanentError wraps an error to signal that retrying should stop.
type PermanentError struct {
	Err error
}

func (e *PermanentError) Error() string { return e.Err.Error() }
func (e *PermanentError) Unwrap() error { return e.Err }

// Permanent wraps err so that Retry stops immediately.
func Permanent(err error) error {
	return &PermanentError{Err: err}
}

// ExponentialBackoff holds configuration for exponential backoff retry.
type ExponentialBackoff struct {
	InitialInterval time.Duration
	MaxInterval     time.Duration
	MaxElapsedTime  time.Duration // 0 means no limit

	// Rand returns a value in [0, 1), used to compute the jitter factor
	// applied to each backoff. Nil uses the package-level math/rand/v2
	// source. Tests set this to a deterministic function for reproducible
	// assertions.
	Rand func() float64

	currentInterval time.Duration
}

// NextBackOff returns the next wait interval: the unjittered doubling
// sequence (InitialInterval, 2x, 4x, ... capped at MaxInterval) multiplied
// by a random factor in [0.5, 1.5) and clamped to [InitialInterval,
// MaxInterval].
//
// The doubling sequence itself is unaffected by the random draw, so it
// keeps climbing to MaxInterval from call to call regardless of how any
// single draw landed. Without jitter, every agent reconnecting after the
// same event (e.g. a shared backhaul server restart) retries on the exact
// same schedule; the random factor spreads that out.
func (b *ExponentialBackoff) NextBackOff() time.Duration {
	if b.currentInterval == 0 {
		b.currentInterval = b.InitialInterval
	} else {
		b.currentInterval = time.Duration(math.Min(
			float64(b.currentInterval)*2,
			float64(b.MaxInterval),
		))
	}

	return b.jitter(b.currentInterval)
}

func (b *ExponentialBackoff) jitter(interval time.Duration) time.Duration {
	randFn := b.Rand
	if randFn == nil {
		randFn = rand.Float64
	}

	factor := 0.5 + randFn()
	jittered := time.Duration(float64(interval) * factor)

	if jittered < b.InitialInterval {
		jittered = b.InitialInterval
	}
	if jittered > b.MaxInterval {
		jittered = b.MaxInterval
	}

	return jittered
}

// Reset resets the backoff interval to initial state.
func (b *ExponentialBackoff) Reset() {
	b.currentInterval = 0
}

// Retry calls operation until it succeeds, returns a PermanentError,
// or the context/elapsed time limit is exceeded.
func Retry(ctx context.Context, b *ExponentialBackoff, operation func() error) error {
	b.Reset()
	start := time.Now()

	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		err := operation()
		if err == nil {
			return nil
		}

		var permanent *PermanentError
		if errors.As(err, &permanent) {
			return permanent.Err
		}

		if b.MaxElapsedTime > 0 && time.Since(start) >= b.MaxElapsedTime {
			return err
		}

		timer := time.NewTimer(b.NextBackOff())

		select {
		case <-ctx.Done():
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			return ctx.Err()
		case <-timer.C:
		}
	}
}
