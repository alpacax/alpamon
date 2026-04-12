package retry

import (
	"context"
	"errors"
	"math"
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
	currentInterval time.Duration
}

// NextBackOff returns the next wait interval, capped at MaxInterval.
func (b *ExponentialBackoff) NextBackOff() time.Duration {
	if b.currentInterval == 0 {
		b.currentInterval = b.InitialInterval
		return b.currentInterval
	}
	b.currentInterval = time.Duration(math.Min(
		float64(b.currentInterval)*2,
		float64(b.MaxInterval),
	))
	return b.currentInterval
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

		interval := b.NextBackOff()

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(interval):
		}
	}
}
