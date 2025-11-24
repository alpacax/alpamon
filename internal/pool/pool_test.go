package pool

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestPoolBasic(t *testing.T) {
	pool := NewPool(3, 10)
	defer pool.Shutdown(5 * time.Second)

	var counter int32
	var wg sync.WaitGroup

	// Submit 10 jobs
	for i := 0; i < 10; i++ {
		wg.Add(1)
		err := pool.Submit(context.Background(), func() error {
			atomic.AddInt32(&counter, 1)
			wg.Done()
			time.Sleep(10 * time.Millisecond)
			return nil
		})
		if err != nil {
			t.Errorf("failed to submit job %d: %v", i, err)
			wg.Done()
		}
	}

	// Wait for all jobs to complete
	wg.Wait()

	if atomic.LoadInt32(&counter) != 10 {
		t.Errorf("expected 10 jobs to complete, got %d", counter)
	}
}

func TestPoolQueueFull(t *testing.T) {
	// Small queue size to test overflow
	// Queue size = 1, Workers = 1
	pool := NewPool(1, 1)
	defer pool.Shutdown(5 * time.Second)

	// Use a channel to control task execution
	blocker := make(chan struct{})

	// Block the worker - this job will be picked up by the worker immediately
	err := pool.Submit(context.Background(), func() error {
		<-blocker // Wait until we signal
		return nil
	})
	if err != nil {
		t.Fatalf("failed to submit blocking task: %v", err)
	}

	// Give worker time to pick up the first job
	time.Sleep(10 * time.Millisecond)

	// Fill the queue (capacity is 1)
	err = pool.Submit(context.Background(), func() error {
		return nil
	})
	if err != nil {
		t.Fatalf("failed to submit to queue: %v", err)
	}

	// This should fail immediately (worker is blocked, queue is full)
	err = pool.Submit(context.Background(), func() error {
		return nil
	})

	if err == nil || err.Error() != "job queue is full" {
		t.Errorf("expected queue full error, got: %v", err)
	}

	// Unblock the worker to allow shutdown
	close(blocker)
}

func TestPoolConcurrency(t *testing.T) {
	maxWorkers := 3
	pool := NewPool(maxWorkers, 100)
	defer pool.Shutdown(5 * time.Second)

	var concurrent int32
	var maxConcurrent int32

	// Submit many jobs
	for i := 0; i < 50; i++ {
		pool.Submit(context.Background(), func() error {
			current := atomic.AddInt32(&concurrent, 1)
			defer atomic.AddInt32(&concurrent, -1)

			// Track max concurrent
			for {
				max := atomic.LoadInt32(&maxConcurrent)
				if current <= max || atomic.CompareAndSwapInt32(&maxConcurrent, max, current) {
					break
				}
			}

			time.Sleep(10 * time.Millisecond)
			return nil
		})
	}

	// Wait a bit for jobs to run
	time.Sleep(200 * time.Millisecond)

	// Max concurrent should not exceed worker count
	if int(maxConcurrent) > maxWorkers {
		t.Errorf("exceeded max concurrency: got %d, want <= %d", maxConcurrent, maxWorkers)
	}
}

func TestPoolPanicRecovery(t *testing.T) {
	pool := NewPool(2, 10)
	defer pool.Shutdown(5 * time.Second)

	var completed int32

	// Submit job that panics
	pool.Submit(context.Background(), func() error {
		panic("test panic")
	})

	// Submit normal job after panic
	err := pool.Submit(context.Background(), func() error {
		atomic.AddInt32(&completed, 1)
		return nil
	})

	if err != nil {
		t.Errorf("failed to submit job after panic: %v", err)
	}

	// Wait for job completion
	time.Sleep(100 * time.Millisecond)

	if atomic.LoadInt32(&completed) != 1 {
		t.Error("normal job did not complete after panic")
	}
}

func TestPoolShutdown(t *testing.T) {
	pool := NewPool(2, 10)

	var completed int32

	// Submit several jobs
	for i := 0; i < 5; i++ {
		pool.Submit(context.Background(), func() error {
			time.Sleep(50 * time.Millisecond)
			atomic.AddInt32(&completed, 1)
			return nil
		})
	}

	// Shutdown with timeout
	err := pool.Shutdown(1 * time.Second)
	if err != nil {
		t.Fatalf("shutdown failed: %v", err)
	}

	// All jobs should have completed
	if atomic.LoadInt32(&completed) != 5 {
		t.Errorf("not all jobs completed: got %d, want 5", completed)
	}

	// New submissions should fail
	err = pool.Submit(context.Background(), func() error { return nil })
	if err == nil {
		t.Error("expected error when submitting to shut down pool")
	}
}

// Benchmark comparison
func BenchmarkPoolSubmit(b *testing.B) {
	pool := NewPool(10, 1000)
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pool.Submit(ctx, func() error {
			return nil
		})
	}

	pool.Shutdown(10 * time.Second)
}
