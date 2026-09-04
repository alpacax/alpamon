package pool

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPool_NoGoroutineLeak leans on Shutdown joining every worker through the pool's
// own WaitGroup, so a nil return is the proof—no runtime.NumGoroutine() tolerance needed.
func TestPool_NoGoroutineLeak(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		pool := NewPool(5, 200)
		ctx := context.Background()

		var wg sync.WaitGroup

		for range 100 {
			wg.Add(1)
			err := pool.Submit(ctx, func() error {
				defer wg.Done()
				time.Sleep(5 * time.Millisecond)
				return nil
			})
			if err != nil {
				wg.Done()
				// Don't fail on queue full - just log it
				t.Logf("job submit failed: %v", err)
			}
		}

		wg.Wait()

		assert.NoError(t, pool.Shutdown(5*time.Second), "shutdown failed")
	})
}

func TestPool_NoLeakAfterPanic(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		pool := NewPool(3, 20)
		defer func() {
			assert.NoError(t, pool.Shutdown(5*time.Second), "shutdown failed")
		}()
		ctx := context.Background()

		var completed atomic.Int32
		var wg sync.WaitGroup

		for i := range 10 {
			require.NoErrorf(t, pool.Submit(ctx, func() error {
				panic("test panic")
			}), "failed to submit panic job %d", i)
		}

		for range 10 {
			wg.Add(1)
			if err := pool.Submit(ctx, func() error {
				defer wg.Done()
				completed.Add(1)
				return nil
			}); err != nil {
				wg.Done()
			}
		}

		// The queue is FIFO, so every normal job finishing proves workers survived the
		// panicking ones; a worker that did not leaves this Wait unsatisfiable.
		wg.Wait()

		assert.NotZero(t, completed.Load(), "no normal jobs completed after panics - workers may have died")
	})
}

func TestPool_NoLeakAfterContextCancel(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		pool := NewPool(5, 100)

		ctx, cancel := context.WithCancel(context.Background())

		started := make(chan struct{})
		var startOnce sync.Once
		var wg sync.WaitGroup
		for range 20 {
			wg.Add(1)
			err := pool.Submit(ctx, func() error {
				defer wg.Done()
				startOnce.Do(func() { close(started) })
				time.Sleep(50 * time.Millisecond)
				return nil
			})
			if err != nil {
				wg.Done()
			}
		}

		<-started
		cancel()

		wg.Wait()

		// The pool is free to check the context or not, so this only records what it did.
		err := pool.Submit(ctx, func() error {
			return nil
		})
		if err != nil {
			t.Logf("submit to cancelled context returned: %v", err)
		}

		assert.NoError(t, pool.Shutdown(5*time.Second), "shutdown failed")
	})
}

func TestPool_NoLeakQueueFull(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		pool := NewPool(1, 2)
		defer func() {
			assert.NoError(t, pool.Shutdown(5*time.Second), "shutdown failed")
		}()
		ctx := context.Background()

		started := make(chan struct{})
		blocker := make(chan struct{})
		// Deferred: a require below would otherwise exit with the worker still parked here, and the bubble would report that leak instead of the failure.
		defer close(blocker)
		require.NoError(t, pool.Submit(ctx, func() error {
			close(started)
			<-blocker
			return nil
		}), "failed to submit the blocking job")

		// The bubble bounds this: a worker that never starts is reported as a deadlock, not a hang.
		<-started

		// Both must land, or the submit below would never reach a full queue.
		require.NoError(t, pool.Submit(ctx, func() error { return nil }))
		require.NoError(t, pool.Submit(ctx, func() error { return nil }))

		err := pool.Submit(ctx, func() error { return nil })
		assert.Error(t, err, "expected queue full error")
	})
}

func TestPool_NoLeakRapidShutdown(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		for i := range 10 {
			// A closure per pool so the shutdown is deferred; a failed submit would otherwise leave this pool's workers running.
			func() {
				pool := NewPool(5, 50)
				// A timeout here means a leaked worker, so stop before more pools compound it.
				defer func() {
					require.NoErrorf(t, pool.Shutdown(1*time.Second), "shutdown %d failed", i)
				}()
				ctx := context.Background()

				for j := range 10 {
					require.NoErrorf(t, pool.Submit(ctx, func() error {
						time.Sleep(5 * time.Millisecond)
						return nil
					}), "pool %d: failed to submit job %d", i, j)
				}
			}()
		}
	})
}
