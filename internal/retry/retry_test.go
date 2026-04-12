package retry

import (
	"context"
	"errors"
	"testing"
	"time"
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
	ctx, cancel := context.WithCancel(context.Background())

	b := &ExponentialBackoff{
		InitialInterval: 1 * time.Second,
		MaxInterval:     1 * time.Second,
	}

	calls := 0
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	err := Retry(ctx, b, func() error {
		calls++
		return errors.New("keep trying")
	})

	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
	if calls < 1 {
		t.Fatal("expected at least 1 call")
	}
}

func TestRetry_MaxElapsedTime(t *testing.T) {
	b := &ExponentialBackoff{
		InitialInterval: 10 * time.Millisecond,
		MaxInterval:     10 * time.Millisecond,
		MaxElapsedTime:  50 * time.Millisecond,
	}

	err := Retry(context.Background(), b, func() error {
		return errors.New("always fail")
	})

	if err == nil {
		t.Fatal("expected error after max elapsed time")
	}
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
