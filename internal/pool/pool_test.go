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

func TestPoolBasic(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		pool := NewPool(3, 10)
		defer func() {
			assert.NoError(t, pool.Shutdown(5*time.Second), "shutdown failed")
		}()

		var counter atomic.Int32
		var wg sync.WaitGroup

		// Submit 10 jobs
		for i := range 10 {
			wg.Add(1)
			err := pool.Submit(context.Background(), func() error {
				defer wg.Done()
				counter.Add(1)
				// Hold the worker so the jobs overlap.
				time.Sleep(10 * time.Millisecond)
				return nil
			})
			require.NoErrorf(t, err, "failed to submit job %d", i)
		}

		// Wait for every job to return, not merely to start: the Done above is
		// deferred, so a worker that never finishes one leaves this Wait
		// unsatisfiable and the bubble reports it as a deadlock.
		wg.Wait()

		assert.Equal(t, int32(10), counter.Load(), "expected 10 jobs to complete")
	})
}

func TestPoolQueueFull(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		// Small queue size to test overflow
		// Queue size = 1, Workers = 1
		pool := NewPool(1, 1)
		defer func() {
			assert.NoError(t, pool.Shutdown(5*time.Second), "shutdown failed")
		}()

		// Use a channel to control task execution
		started := make(chan struct{})
		blocker := make(chan struct{})

		// Block the worker - this job will be picked up by the worker immediately
		err := pool.Submit(context.Background(), func() error {
			close(started)
			<-blocker // Wait until we signal
			return nil
		})
		require.NoError(t, err, "failed to submit blocking task")

		// Once this returns, the worker has taken the job off the queue and the queue
		// is empty again. Nothing here needs a fake clock; the bubble is what bounds
		// the wait, reporting a worker that never starts as a deadlock rather than
		// hanging until the package timeout.
		<-started

		// Fill the queue (capacity is 1)
		err = pool.Submit(context.Background(), func() error {
			return nil
		})
		require.NoError(t, err, "failed to submit to queue")

		// This should fail immediately (worker is blocked, queue is full)
		err = pool.Submit(context.Background(), func() error {
			return nil
		})

		assert.EqualError(t, err, "job queue is full")

		// Unblock the worker to allow shutdown
		close(blocker)
	})
}

// TestPool_SaturatesWithoutExceedingWorkers pins that the pool runs exactly as many
// jobs at once as it has workers—never more, and never fewer once the queue can fill them.
func TestPool_SaturatesWithoutExceedingWorkers(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const (
			maxWorkers = 10
			taskCount  = 50
		)

		pool := NewPool(maxWorkers, taskCount)
		defer func() {
			assert.NoError(t, pool.Shutdown(5*time.Second), "shutdown failed")
		}()

		var maxConcurrent int
		var current int
		var mu sync.Mutex

		var wg sync.WaitGroup
		for i := range taskCount {
			wg.Add(1)
			err := pool.Submit(context.Background(), func() error {
				defer wg.Done()

				mu.Lock()
				current++
				if current > maxConcurrent {
					maxConcurrent = current
				}
				mu.Unlock()

				// Hold the worker so the jobs actually overlap.
				time.Sleep(20 * time.Millisecond)

				mu.Lock()
				current--
				mu.Unlock()

				return nil
			})
			require.NoErrorf(t, err, "failed to submit job %d", i)
		}

		wg.Wait()

		assert.Equal(t, maxWorkers, maxConcurrent, "the pool must saturate its workers, and never exceed them")
	})
}

func TestPoolPanicRecovery(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		pool := NewPool(2, 10)
		defer func() {
			assert.NoError(t, pool.Shutdown(5*time.Second), "shutdown failed")
		}()

		var completed atomic.Int32
		done := make(chan struct{})

		// Submit job that panics
		require.NoError(t, pool.Submit(context.Background(), func() error {
			panic("test panic")
		}), "failed to submit panic job")

		// Submit normal job after panic
		err := pool.Submit(context.Background(), func() error {
			completed.Add(1)
			close(done)
			return nil
		})
		require.NoError(t, err, "failed to submit job after panic")

		// A worker lost to the panic never reaches this job, and the bubble
		// settles instead of burning five real seconds waiting for the guard.
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("normal job did not complete after panic")
		}

		assert.Equal(t, int32(1), completed.Load())
	})
}

func TestPoolShutdown(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		pool := NewPool(2, 10)

		var completed atomic.Int32

		for i := range 5 {
			err := pool.Submit(context.Background(), func() error {
				time.Sleep(50 * time.Millisecond)
				completed.Add(1)
				return nil
			})
			require.NoErrorf(t, err, "failed to submit job %d", i)
		}

		require.NoError(t, pool.Shutdown(1*time.Second), "shutdown failed")

		// All jobs should have completed
		assert.Equal(t, int32(5), completed.Load(), "not all jobs completed")

		// New submissions should fail
		assert.Error(t, pool.Submit(context.Background(), func() error { return nil }),
			"expected error when submitting to shut down pool")
	})
}

// Benchmark comparison
func BenchmarkPoolSubmit(b *testing.B) {
	pool := NewPool(10, 50000)
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Ignore queue full errors in benchmark
		_ = pool.Submit(ctx, func() error {
			return nil
		})
	}
	b.StopTimer()

	if err := pool.Shutdown(10 * time.Second); err != nil {
		b.Errorf("shutdown failed: %v", err)
	}
}
