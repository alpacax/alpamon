package agent

import (
	"context"
	"testing"
	"time"
)

// TestContextManagerCreation verifies context manager initialization
func TestContextManagerCreation(t *testing.T) {
	cm := NewContextManager()
	if cm == nil {
		t.Fatal("NewContextManager returned nil")
	}

	if cm.IsShutdown() {
		t.Error("new context manager should not be shutdown")
	}

	// Root context should be active
	select {
	case <-cm.Root().Done():
		t.Error("root context should not be cancelled")
	default:
		// Expected
	}
}

// TestContextCancellation verifies that shutdown cancels all child contexts
func TestContextCancellation(t *testing.T) {
	cm := NewContextManager()

	// Create multiple child contexts
	ctx1, cancel1 := cm.NewContext(0)
	defer cancel1()

	ctx2, cancel2 := cm.NewContext(5 * time.Second)
	defer cancel2()

	ctx3, cancel3 := cm.NewContext(0)
	defer cancel3()

	// Shutdown the manager
	cm.Shutdown()

	// All contexts should be cancelled
	for i, ctx := range []context.Context{ctx1, ctx2, ctx3} {
		select {
		case <-ctx.Done():
			// Expected
		case <-time.After(100 * time.Millisecond):
			t.Errorf("context %d not cancelled after shutdown", i+1)
		}
	}

	// Manager should report as shutdown
	if !cm.IsShutdown() {
		t.Error("IsShutdown() should return true after Shutdown()")
	}
}

// TestContextTimeout verifies timeout context creation
func TestContextTimeout(t *testing.T) {
	cm := NewContextManager()
	defer cm.Shutdown()

	// Create context with timeout
	ctx, cancel := cm.NewContext(50 * time.Millisecond)
	defer cancel()

	// Should timeout
	select {
	case <-ctx.Done():
		if ctx.Err() != context.DeadlineExceeded {
			t.Errorf("expected DeadlineExceeded, got %v", ctx.Err())
		}
	case <-time.After(100 * time.Millisecond):
		t.Error("context did not timeout")
	}
}

// TestContextDeadline verifies deadline context creation
func TestContextDeadline(t *testing.T) {
	cm := NewContextManager()
	defer cm.Shutdown()

	deadline := time.Now().Add(50 * time.Millisecond)
	ctx, cancel := cm.NewContextWithDeadline(deadline)
	defer cancel()

	// Should respect deadline
	select {
	case <-ctx.Done():
		if ctx.Err() != context.DeadlineExceeded {
			t.Errorf("expected DeadlineExceeded, got %v", ctx.Err())
		}
	case <-time.After(100 * time.Millisecond):
		t.Error("context did not respect deadline")
	}
}

// TestContextNoTimeout verifies context without timeout
func TestContextNoTimeout(t *testing.T) {
	cm := NewContextManager()
	defer cm.Shutdown()

	// Create context without timeout (0 duration)
	ctx, cancel := cm.NewContext(0)
	defer cancel()

	// Should not timeout on its own
	select {
	case <-ctx.Done():
		t.Error("context should not be cancelled without explicit cancellation")
	case <-time.After(100 * time.Millisecond):
		// Expected
	}

	// Manual cancellation should work
	cancel()
	select {
	case <-ctx.Done():
		// Expected
	case <-time.After(100 * time.Millisecond):
		t.Error("context not cancelled after explicit cancel")
	}
}

// TestConcurrentContextCreation verifies thread-safe context creation
func TestConcurrentContextCreation(t *testing.T) {
	cm := NewContextManager()
	defer cm.Shutdown()

	done := make(chan bool)

	// Create contexts concurrently
	for i := 0; i < 100; i++ {
		go func(id int) {
			ctx, cancel := cm.NewContext(time.Duration(id) * time.Millisecond)
			defer cancel()

			// Do some work
			select {
			case <-ctx.Done():
				// Timeout expected for non-zero durations
			case <-time.After(200 * time.Millisecond):
				// Maximum wait
			}

			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < 100; i++ {
		select {
		case <-done:
			// Continue
		case <-time.After(5 * time.Second):
			t.Fatal("concurrent operations timed out")
		}
	}

	// Context manager should still be functional
	ctx, cancel := cm.NewContext(0)
	cancel()
	select {
	case <-ctx.Done():
		// Expected
	default:
		t.Error("context manager not functional after concurrent operations")
	}
}

// TestShutdownIdempotency verifies that Shutdown can be called multiple times
func TestShutdownIdempotency(t *testing.T) {
	cm := NewContextManager()

	// Create a context
	ctx, cancel := cm.NewContext(0)
	defer cancel()

	// Shutdown multiple times
	cm.Shutdown()
	cm.Shutdown() // Should not panic
	cm.Shutdown() // Should not panic

	// Context should still be cancelled
	select {
	case <-ctx.Done():
		// Expected
	default:
		t.Error("context not cancelled after shutdown")
	}

	// IsShutdown should still return true
	if !cm.IsShutdown() {
		t.Error("IsShutdown() should return true after multiple shutdowns")
	}
}
