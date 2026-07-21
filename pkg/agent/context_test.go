package agent

import (
	"context"
	"errors"
	"sync"
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

// TestShutdownCancelsChildren checks cancellation propagation and shutdown state; the
// manager only wraps context.WithCancel/WithTimeout, so it spawns no goroutines to leak.
func TestShutdownCancelsChildren(t *testing.T) {
	cm := NewContextManager()

	ctx, cancel := cm.NewContext(0)
	cancel()
	if !errors.Is(ctx.Err(), context.Canceled) {
		t.Errorf("cancelled child: got %v, want context.Canceled", ctx.Err())
	}

	// A child left open before Shutdown must be cancelled by Shutdown.
	child, childCancel := cm.NewContext(0)
	defer childCancel()
	cm.Shutdown()

	if !cm.IsShutdown() {
		t.Error("IsShutdown() = false after Shutdown()")
	}
	if !errors.Is(child.Err(), context.Canceled) {
		t.Errorf("child after Shutdown: got %v, want context.Canceled", child.Err())
	}
}

// TestChildCleanup verifies child context cleanup on parent shutdown.
func TestChildCleanup(t *testing.T) {
	cm := NewContextManager()

	// Each child blocks purely on cancellation with no self-exit timer, so the
	// goroutines drain only if Shutdown actually cancels them; otherwise the
	// outer guard below fires and the test fails.
	var wg sync.WaitGroup
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, cancel := cm.NewContext(5 * time.Second)
			defer cancel()
			<-ctx.Done()
		}()
	}

	// Give some time for goroutines to start
	time.Sleep(20 * time.Millisecond)

	// Shutdown manager - should cancel all child contexts
	cm.Shutdown()

	// Wait for all goroutines to exit
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// All goroutines exited
	case <-time.After(2 * time.Second):
		t.Error("child goroutines did not exit after parent shutdown")
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
	for i := range 100 {
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
	for range 100 {
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

// TestRapidCreateCancel exercises rapid create/cancel churn. Asserts ctx.Err() != nil, not
// == Canceled: a short timeout may fire before cancel(), making the error DeadlineExceeded.
func TestRapidCreateCancel(t *testing.T) {
	for i := range 20 {
		cm := NewContextManager()

		for j := range 50 {
			ctx, cancel := cm.NewContext(time.Duration(j) * time.Millisecond)
			cancel()
			if ctx.Err() == nil {
				t.Fatalf("cycle %d/%d: child not done after cancel", i, j)
			}
		}

		cm.Shutdown()
		if !cm.IsShutdown() {
			t.Fatalf("cycle %d: IsShutdown() = false after Shutdown()", i)
		}
	}
}

// TestConcurrentOperations verifies thread safety under concurrent access.
func TestConcurrentOperations(t *testing.T) {
	cm := NewContextManager()

	var wg sync.WaitGroup

	// Concurrent context creation
	for i := range 50 {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := range 10 {
				ctx, cancel := cm.NewContext(time.Duration(id+j) * time.Millisecond)
				select {
				case <-ctx.Done():
				case <-time.After(50 * time.Millisecond):
				}
				cancel()
			}
		}(i)
	}

	// Wait for all operations
	wg.Wait()

	// Manager must remain functional after the concurrent churn.
	ctx, cancel := cm.NewContext(0)
	cancel()
	select {
	case <-ctx.Done():
		// Expected
	default:
		t.Error("context manager not functional after concurrent operations")
	}

	// Shutdown
	cm.Shutdown()
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
