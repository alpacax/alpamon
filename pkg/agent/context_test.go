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

func TestContextManagerCreation(t *testing.T) {
	cm := NewContextManager()
	require.NotNil(t, cm, "NewContextManager returned nil")

	assert.False(t, cm.IsShutdown(), "new context manager should not be shutdown")
	assert.NoError(t, cm.Root().Err(), "root context should not be cancelled")
}

func TestContextCancellation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		cm := NewContextManager()

		ctx1, cancel1 := cm.NewContext(0)
		defer cancel1()

		ctx2, cancel2 := cm.NewContext(5 * time.Second)
		defer cancel2()

		ctx3, cancel3 := cm.NewContext(0)
		defer cancel3()

		cm.Shutdown()

		// Cancellation reaches the children before Shutdown returns, so nothing has to wait here.
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

func TestChildCleanup(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		cm := NewContextManager()

		// No child has a self-exit timer, so these drain only if Shutdown really cancels them.
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

		cm.Shutdown()

		wg.Wait()
	})
}

func TestContextTimeout(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		cm := NewContextManager()
		defer cm.Shutdown()

		ctx, cancel := cm.NewContext(50 * time.Millisecond)
		defer cancel()

		start := time.Now()
		<-ctx.Done()

		assert.ErrorIs(t, ctx.Err(), context.DeadlineExceeded)
		assert.Equal(t, 50*time.Millisecond, time.Since(start), "the deadline must land on the timeout itself")
	})
}

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

func TestContextNoTimeout(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		cm := NewContextManager()
		defer cm.Shutdown()

		ctx, cancel := cm.NewContext(0)
		defer cancel()

		// A zero timeout arms no timer, so settling the bubble is the whole proof.
		synctest.Wait()
		assert.NoError(t, ctx.Err(), "context should not be cancelled without explicit cancellation")

		cancel()
		assert.ErrorIs(t, ctx.Err(), context.Canceled, "context not cancelled after explicit cancel")
	})
}

func TestConcurrentContextCreation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		cm := NewContextManager()
		defer cm.Shutdown()

		done := make(chan bool)

		for i := range 100 {
			go func(id int) {
				ctx, cancel := cm.NewContext(time.Duration(id) * time.Millisecond)
				defer cancel()

				select {
				case <-ctx.Done():
				case <-time.After(200 * time.Millisecond):
				}

				done <- true
			}(i)
		}

		// A goroutine that never reports leaves this receive unsatisfiable, and the bubble names it.
		for range 100 {
			<-done
		}

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

func TestConcurrentOperations(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		cm := NewContextManager()

		var wg sync.WaitGroup

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

		wg.Wait()

		ctx, cancel := cm.NewContext(0)
		cancel()
		assert.ErrorIs(t, ctx.Err(), context.Canceled, "context manager not functional after concurrent operations")

		cm.Shutdown()
	})
}

func TestShutdownIdempotency(t *testing.T) {
	cm := NewContextManager()

	ctx, cancel := cm.NewContext(0)
	defer cancel()

	cm.Shutdown()
	cm.Shutdown() // Should not panic
	cm.Shutdown() // Should not panic

	assert.ErrorIs(t, ctx.Err(), context.Canceled, "context not cancelled after shutdown")
	assert.True(t, cm.IsShutdown(), "IsShutdown() should return true after multiple shutdowns")
}
