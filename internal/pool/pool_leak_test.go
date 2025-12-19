package pool

import (
	"context"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestPool_NoGoroutineLeak verifies that goroutines are properly cleaned up after normal operations
func TestPool_NoGoroutineLeak(t *testing.T) {
	// Allow garbage collection and goroutine cleanup
	runtime.GC()
	time.Sleep(50 * time.Millisecond)

	initial := runtime.NumGoroutine()

	// Use larger queue size to avoid queue full errors
	pool := NewPool(5, 200)
	ctx := context.Background()

	var wg sync.WaitGroup

	// Submit 100 jobs
	for i := 0; i < 100; i++ {
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

	// Wait for all jobs to complete
	wg.Wait()

	// Shutdown pool
	if err := pool.Shutdown(5 * time.Second); err != nil {
		t.Errorf("shutdown failed: %v", err)
	}

	// Allow goroutines to exit
	runtime.GC()
	time.Sleep(100 * time.Millisecond)

	final := runtime.NumGoroutine()

	// Allow some margin for test runtime and background goroutines
	if final > initial+3 {
		t.Errorf("goroutine leak detected: initial=%d, final=%d (delta=%d)", initial, final, final-initial)
	}
}

// TestPool_NoLeakAfterPanic verifies goroutines are cleaned up after panic recovery
func TestPool_NoLeakAfterPanic(t *testing.T) {
	runtime.GC()
	time.Sleep(50 * time.Millisecond)

	initial := runtime.NumGoroutine()

	pool := NewPool(3, 20)
	ctx := context.Background()

	var completed int32

	// Submit jobs that panic
	for i := 0; i < 10; i++ {
		_ = pool.Submit(ctx, func() error {
			panic("test panic")
		})
	}

	// Submit normal jobs after panics
	for i := 0; i < 10; i++ {
		_ = pool.Submit(ctx, func() error {
			atomic.AddInt32(&completed, 1)
			return nil
		})
	}

	// Wait for jobs to process
	time.Sleep(200 * time.Millisecond)

	// Shutdown pool
	if err := pool.Shutdown(5 * time.Second); err != nil {
		t.Errorf("shutdown failed: %v", err)
	}

	runtime.GC()
	time.Sleep(100 * time.Millisecond)

	final := runtime.NumGoroutine()

	if final > initial+3 {
		t.Errorf("goroutine leak after panic: initial=%d, final=%d (delta=%d)", initial, final, final-initial)
	}

	if atomic.LoadInt32(&completed) == 0 {
		t.Error("no normal jobs completed after panics - workers may have died")
	}
}

// TestPool_NoLeakAfterContextCancel verifies goroutines are cleaned up after context cancellation
func TestPool_NoLeakAfterContextCancel(t *testing.T) {
	runtime.GC()
	time.Sleep(50 * time.Millisecond)

	initial := runtime.NumGoroutine()

	pool := NewPool(5, 100)

	// Submit some jobs with cancelable context
	ctx, cancel := context.WithCancel(context.Background())

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		err := pool.Submit(ctx, func() error {
			defer wg.Done()
			time.Sleep(50 * time.Millisecond)
			return nil
		})
		if err != nil {
			wg.Done()
		}
	}

	// Cancel context while jobs are running
	time.Sleep(10 * time.Millisecond)
	cancel()

	// Wait for running jobs to complete
	wg.Wait()

	// Try to submit more jobs with cancelled context
	// Note: Pool may or may not check context before submission depending on implementation
	err := pool.Submit(ctx, func() error {
		return nil
	})
	// Just log the result - this tests if the pool handles cancelled context
	if err != nil {
		t.Logf("submit to cancelled context returned: %v", err)
	}

	// Shutdown pool
	if err := pool.Shutdown(5 * time.Second); err != nil {
		t.Errorf("shutdown failed: %v", err)
	}

	runtime.GC()
	time.Sleep(100 * time.Millisecond)

	final := runtime.NumGoroutine()

	if final > initial+3 {
		t.Errorf("goroutine leak after context cancel: initial=%d, final=%d (delta=%d)", initial, final, final-initial)
	}
}

// TestPool_NoLeakQueueFull verifies goroutines are cleaned up when queue is full
func TestPool_NoLeakQueueFull(t *testing.T) {
	runtime.GC()
	time.Sleep(50 * time.Millisecond)

	initial := runtime.NumGoroutine()

	// Small pool and queue to trigger queue full
	pool := NewPool(1, 2)
	ctx := context.Background()

	// Block the worker
	blocker := make(chan struct{})
	_ = pool.Submit(ctx, func() error {
		<-blocker
		return nil
	})

	// Wait for worker to pick up the blocking job
	time.Sleep(10 * time.Millisecond)

	// Fill the queue
	_ = pool.Submit(ctx, func() error { return nil })
	_ = pool.Submit(ctx, func() error { return nil })

	// This should fail - queue full
	err := pool.Submit(ctx, func() error { return nil })
	if err == nil {
		t.Error("expected queue full error")
	}

	// Unblock and shutdown
	close(blocker)

	if err := pool.Shutdown(5 * time.Second); err != nil {
		t.Errorf("shutdown failed: %v", err)
	}

	runtime.GC()
	time.Sleep(100 * time.Millisecond)

	final := runtime.NumGoroutine()

	if final > initial+3 {
		t.Errorf("goroutine leak after queue full: initial=%d, final=%d (delta=%d)", initial, final, final-initial)
	}
}

// TestPool_NoLeakRapidShutdown verifies goroutines are cleaned up on rapid shutdown
func TestPool_NoLeakRapidShutdown(t *testing.T) {
	runtime.GC()
	time.Sleep(50 * time.Millisecond)

	initial := runtime.NumGoroutine()

	// Create and shutdown multiple pools rapidly
	for i := 0; i < 10; i++ {
		pool := NewPool(5, 50)
		ctx := context.Background()

		// Submit a few jobs
		for j := 0; j < 10; j++ {
			_ = pool.Submit(ctx, func() error {
				time.Sleep(5 * time.Millisecond)
				return nil
			})
		}

		// Shutdown immediately
		if err := pool.Shutdown(1 * time.Second); err != nil {
			t.Logf("shutdown %d failed: %v", i, err)
		}
	}

	runtime.GC()
	time.Sleep(200 * time.Millisecond)

	final := runtime.NumGoroutine()

	if final > initial+5 {
		t.Errorf("goroutine leak after rapid shutdowns: initial=%d, final=%d (delta=%d)", initial, final, final-initial)
	}
}

// TestPool_MaxGoroutineEnforcement verifies max concurrent goroutines are enforced
func TestPool_MaxGoroutineEnforcement(t *testing.T) {
	maxWorkers := 10
	pool := NewPool(maxWorkers, 100)
	defer func() { _ = pool.Shutdown(5 * time.Second) }()

	var maxConcurrent int32
	var concurrent int32

	ctx := context.Background()

	for i := 0; i < 100; i++ {
		_ = pool.Submit(ctx, func() error {
			current := atomic.AddInt32(&concurrent, 1)
			defer atomic.AddInt32(&concurrent, -1)

			// Track max concurrent
			for {
				max := atomic.LoadInt32(&maxConcurrent)
				if current <= max || atomic.CompareAndSwapInt32(&maxConcurrent, max, current) {
					break
				}
			}

			time.Sleep(50 * time.Millisecond)
			return nil
		})
	}

	// Wait for all jobs to complete
	time.Sleep(600 * time.Millisecond)

	if int(maxConcurrent) > maxWorkers {
		t.Errorf("max concurrent workers %d exceeded limit %d", maxConcurrent, maxWorkers)
	}
}
