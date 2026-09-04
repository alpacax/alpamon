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

	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if calls != 3 {
		t.Fatalf("expected 3 calls, got %d", calls)
	}
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

	if !errors.Is(err, fatal) {
		t.Fatalf("expected fatal error, got %v", err)
	}
	if calls != 1 {
		t.Fatalf("expected 1 call (no retry after permanent), got %d", calls)
	}
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
		// The bubble's clock is exact, so the stop lands on MaxElapsedTime itself.
		// A ">=" here would also pass for a retry loop that overran it.
		assert.Equal(t, 50*time.Millisecond, time.Since(start), "the give-up must land on MaxElapsedTime")
	})
}

func TestNextBackOff_CappedAtMax(t *testing.T) {
	b := &ExponentialBackoff{
		InitialInterval: 100 * time.Millisecond,
		MaxInterval:     500 * time.Millisecond,
	}

	intervals := make([]time.Duration, 6)
	for i := range intervals {
		intervals[i] = b.NextBackOff()
	}

	// First should be InitialInterval
	if intervals[0] != 100*time.Millisecond {
		t.Fatalf("first interval = %v, want 100ms", intervals[0])
	}

	// All should be <= MaxInterval
	for i, d := range intervals {
		if d > 500*time.Millisecond {
			t.Fatalf("interval[%d] = %v exceeds max 500ms", i, d)
		}
	}

	// Last ones should be capped at MaxInterval
	if intervals[5] != 500*time.Millisecond {
		t.Fatalf("interval[5] = %v, want 500ms (capped)", intervals[5])
	}
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
