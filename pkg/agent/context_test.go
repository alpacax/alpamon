package agent

import (
	"context"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestContextManagerCreation verifies context manager initialization
func TestContextManagerCreation(t *testing.T) {
	cm := NewContextManager()
	require.NotNil(t, cm, "NewContextManager returned nil")

	assert.False(t, cm.IsShutdown(), "new context manager should not be shutdown")
	assert.NoError(t, cm.Root().Err(), "root context should not be cancelled")
}

// TestContextCancellation verifies that shutdown cancels all child contexts
func TestContextCancellation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
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
			assert.ErrorIsf(t, ctx.Err(), context.Canceled, "context %d not cancelled after shutdown", i+1)
		}

		assert.True(t, cm.IsShutdown(), "IsShutdown() should return true after Shutdown()")
	})
}

// TestShutdownCancelsChildren checks cancellation propagation and shutdown state; the
// manager only wraps context.WithCancel/WithTimeout, so it spawns no goroutines to leak.
func TestShutdownCancelsChildren(t *testing.T) {
	cm := NewContextManager()

	ctx, cancel := cm.NewContext(0)
	cancel()
	assert.ErrorIs(t, ctx.Err(), context.Canceled, "cancelled child")

	// A child left open before Shutdown must be cancelled by Shutdown.
	child, childCancel := cm.NewContext(0)
	defer childCancel()
	cm.Shutdown()

	assert.True(t, cm.IsShutdown(), "IsShutdown() = false after Shutdown()")
	assert.ErrorIs(t, child.Err(), context.Canceled, "child after Shutdown")
}

// TestChildCleanup verifies child context cleanup on parent shutdown.
func TestChildCleanup(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		cm := NewContextManager()

		// Each child blocks purely on cancellation with no self-exit timer, so the
		// goroutines drain only if Shutdown actually cancels them; otherwise the
		// outer guard below fires and the test fails.
		var registered sync.WaitGroup
		registered.Add(20)

		var wg sync.WaitGroup
		for range 20 {
			wg.Go(func() {
				ctx, cancel := cm.NewContext(0)
				defer cancel()
				registered.Done()
				<-ctx.Done()
			})
		}

		// Shutdown proves nothing about children the manager has not seen yet.
		registered.Wait()

		// Shutdown manager - should cancel all child contexts
		cm.Shutdown()

		wg.Wait()
	})
}

// TestContextTimeout verifies timeout context creation
func TestContextTimeout(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		cm := NewContextManager()
		defer cm.Shutdown()

		// Create context with timeout
		ctx, cancel := cm.NewContext(50 * time.Millisecond)
		defer cancel()

		start := time.Now()
		<-ctx.Done()

		assert.ErrorIs(t, ctx.Err(), context.DeadlineExceeded)
		assert.Equal(t, 50*time.Millisecond, time.Since(start), "the deadline must land on the timeout itself")
	})
}

// TestContextDeadline verifies deadline context creation
func TestContextDeadline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		cm := NewContextManager()
		defer cm.Shutdown()

		start := time.Now()
		ctx, cancel := cm.NewContextWithDeadline(start.Add(50 * time.Millisecond))
		defer cancel()

		<-ctx.Done()

		assert.ErrorIs(t, ctx.Err(), context.DeadlineExceeded)
		assert.Equal(t, 50*time.Millisecond, time.Since(start), "the context must run to its deadline, no further")
	})
}

// TestContextNoTimeout verifies context without timeout
func TestContextNoTimeout(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		cm := NewContextManager()
		defer cm.Shutdown()

		// Create context without timeout (0 duration)
		ctx, cancel := cm.NewContext(0)
		defer cancel()

		// A zero timeout arms no timer, so settling the bubble is the whole proof.
		synctest.Wait()
		assert.NoError(t, ctx.Err(), "context should not be cancelled without explicit cancellation")

		// Manual cancellation should work
		cancel()
		assert.ErrorIs(t, ctx.Err(), context.Canceled, "context not cancelled after explicit cancel")
	})
}

// TestConcurrentContextCreation verifies thread-safe context creation
func TestConcurrentContextCreation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
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
			<-done
		}

		// Context manager should still be functional
		ctx, cancel := cm.NewContext(0)
		cancel()
		assert.ErrorIs(t, ctx.Err(), context.Canceled, "context manager not functional after concurrent operations")
	})
}

// TestRapidCreateCancel exercises rapid create/cancel churn. Asserts ctx.Err() != nil, not
// == Canceled: a short timeout may fire before cancel(), making the error DeadlineExceeded.
func TestRapidCreateCancel(t *testing.T) {
	for i := range 20 {
		cm := NewContextManager()

		for j := range 50 {
			ctx, cancel := cm.NewContext(time.Duration(j) * time.Millisecond)
			cancel()
			require.Errorf(t, ctx.Err(), "cycle %d/%d: child not done after cancel", i, j)
		}

		cm.Shutdown()
		require.Truef(t, cm.IsShutdown(), "cycle %d: IsShutdown() = false after Shutdown()", i)
	}
}

// TestConcurrentOperations verifies thread safety under concurrent access.
func TestConcurrentOperations(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
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
		assert.ErrorIs(t, ctx.Err(), context.Canceled, "context manager not functional after concurrent operations")

		// Shutdown
		cm.Shutdown()
	})
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

	assert.ErrorIs(t, ctx.Err(), context.Canceled, "context not cancelled after shutdown")
	assert.True(t, cm.IsShutdown(), "IsShutdown() should return true after multiple shutdowns")
}
