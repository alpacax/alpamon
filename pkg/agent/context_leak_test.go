package agent

import (
	"runtime"
	"sync"
	"testing"
	"time"
)

// TestContextManager_NoGoroutineLeak verifies that goroutines are properly cleaned up
func TestContextManager_NoGoroutineLeak(t *testing.T) {
	runtime.GC()
	time.Sleep(50 * time.Millisecond)

	initial := runtime.NumGoroutine()

	cm := NewContextManager()

	// Create many contexts
	var cancels []func()
	for i := 0; i < 100; i++ {
		_, cancel := cm.NewContext(0)
		cancels = append(cancels, cancel)
	}

	// Create contexts with timeout
	for i := 0; i < 50; i++ {
		_, cancel := cm.NewContext(100 * time.Millisecond)
		cancels = append(cancels, cancel)
	}

	// Cancel all contexts
	for _, cancel := range cancels {
		cancel()
	}

	// Shutdown manager
	cm.Shutdown()

	runtime.GC()
	time.Sleep(200 * time.Millisecond)

	final := runtime.NumGoroutine()

	if final > initial+3 {
		t.Errorf("goroutine leak detected: initial=%d, final=%d (delta=%d)", initial, final, final-initial)
	}
}

// TestContextManager_RapidCreateCancel verifies no leak with rapid create/cancel cycles
func TestContextManager_RapidCreateCancel(t *testing.T) {
	runtime.GC()
	time.Sleep(50 * time.Millisecond)

	initial := runtime.NumGoroutine()

	// Create and shutdown multiple managers rapidly
	for i := 0; i < 20; i++ {
		cm := NewContextManager()

		// Create and immediately cancel contexts
		for j := 0; j < 50; j++ {
			ctx, cancel := cm.NewContext(time.Duration(j) * time.Millisecond)
			_ = ctx
			cancel()
		}

		cm.Shutdown()
	}

	runtime.GC()
	time.Sleep(200 * time.Millisecond)

	final := runtime.NumGoroutine()

	if final > initial+3 {
		t.Errorf("goroutine leak after rapid create/cancel: initial=%d, final=%d (delta=%d)", initial, final, final-initial)
	}
}

// TestContextManager_ChildCleanup verifies child context cleanup on parent shutdown
func TestContextManager_ChildCleanup(t *testing.T) {
	runtime.GC()
	time.Sleep(50 * time.Millisecond)

	initial := runtime.NumGoroutine()

	cm := NewContextManager()

	// Create child contexts that simulate long-running operations
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, cancel := cm.NewContext(5 * time.Second)
			defer cancel()

			// Simulate work
			select {
			case <-ctx.Done():
				// Context was cancelled
			case <-time.After(100 * time.Millisecond):
				// Work completed normally
			}
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

	runtime.GC()
	time.Sleep(100 * time.Millisecond)

	final := runtime.NumGoroutine()

	if final > initial+3 {
		t.Errorf("goroutine leak after child cleanup: initial=%d, final=%d (delta=%d)", initial, final, final-initial)
	}
}

// TestContextManager_ConcurrentOperations verifies thread safety and no leaks under concurrent access
func TestContextManager_ConcurrentOperations(t *testing.T) {
	runtime.GC()
	time.Sleep(50 * time.Millisecond)

	initial := runtime.NumGoroutine()

	cm := NewContextManager()

	var wg sync.WaitGroup

	// Concurrent context creation
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < 10; j++ {
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

	// Shutdown
	cm.Shutdown()

	runtime.GC()
	time.Sleep(200 * time.Millisecond)

	final := runtime.NumGoroutine()

	if final > initial+3 {
		t.Errorf("goroutine leak after concurrent ops: initial=%d, final=%d (delta=%d)", initial, final, final-initial)
	}
}
