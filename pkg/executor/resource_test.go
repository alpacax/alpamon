package executor

import (
	"context"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/alpacax/alpamon/internal/pool"
	"github.com/alpacax/alpamon/pkg/agent"
	"github.com/alpacax/alpamon/pkg/executor/handlers/common"
)

// TestPerformance_MemoryUsageIdle verifies idle memory usage is within limits
func TestPerformance_MemoryUsageIdle(t *testing.T) {
	// Force garbage collection before measuring
	runtime.GC()
	time.Sleep(50 * time.Millisecond)

	// Create typical components
	registry := NewRegistry()
	workerPool := pool.NewPool(10, 100)
	ctxManager := agent.NewContextManager()

	// Register a mock handler
	handler := &MockHandler{
		name:     "test",
		commands: []string{"cmd1"},
	}
	_ = registry.Register(handler)

	// Force garbage collection and let things settle
	runtime.GC()
	time.Sleep(100 * time.Millisecond)

	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	// Calculate total memory in use (HeapAlloc is current heap usage)
	memUsedMB := float64(m.HeapAlloc) / 1024 / 1024

	t.Logf("Heap memory in use: %.2f MB (HeapAlloc: %d bytes)", memUsedMB, m.HeapAlloc)

	// Cleanup
	_ = workerPool.Shutdown(5 * time.Second)
	ctxManager.Shutdown()
	registry.Clear()

	// Allow significant margin - components should use well under 50MB
	// This is a sanity check, not a strict performance requirement
	// Note: This measures total heap, not just our components
	if memUsedMB > 50 {
		t.Errorf("Idle heap memory %.2f MB exceeds 50MB limit", memUsedMB)
	}
}

// TestPerformance_StartupTime verifies component startup is fast
func TestPerformance_StartupTime(t *testing.T) {
	start := time.Now()

	// Create components
	registry := NewRegistry()
	workerPool := pool.NewPool(10, 100)
	ctxManager := agent.NewContextManager()

	// Register some handlers
	for i := 0; i < 10; i++ {
		handler := &MockHandler{
			name:     "handler" + string(rune('A'+i)),
			commands: []string{"cmd" + string(rune('A'+i))},
		}
		_ = registry.Register(handler)
	}

	startupTime := time.Since(start)

	t.Logf("Startup time: %v", startupTime)

	// Cleanup
	_ = workerPool.Shutdown(5 * time.Second)
	ctxManager.Shutdown()
	registry.Clear()

	// Startup should be under 1 second
	if startupTime > 1*time.Second {
		t.Errorf("Startup time %v exceeds 1 second limit", startupTime)
	}
}

// TestPerformance_CommandOverhead measures command execution overhead
func TestPerformance_CommandOverhead(t *testing.T) {
	registry := NewRegistry()

	handler := &IntegrationMockHandler{
		name:           "perf_handler",
		commands:       []string{"perf_cmd"},
		executionDelay: 0, // No delay - measure pure overhead
	}
	_ = registry.Register(handler)

	h, _ := registry.Get("perf_cmd")
	ctx := context.Background()
	args := &common.CommandArgs{}

	// Warm up
	for i := 0; i < 10; i++ {
		_, _, _ = h.Execute(ctx, "perf_cmd", args)
	}

	// Measure execution time
	iterations := 1000
	start := time.Now()

	for i := 0; i < iterations; i++ {
		_, _, _ = h.Execute(ctx, "perf_cmd", args)
	}

	elapsed := time.Since(start)
	avgOverhead := elapsed / time.Duration(iterations)

	t.Logf("Average command overhead: %v (total: %v for %d iterations)", avgOverhead, elapsed, iterations)

	// Each command execution should have minimal overhead (< 1ms)
	if avgOverhead > 1*time.Millisecond {
		t.Errorf("Average command overhead %v exceeds 1ms limit", avgOverhead)
	}
}

// TestPerformance_ConcurrentCommandScaling tests performance under concurrent load
func TestPerformance_ConcurrentCommandScaling(t *testing.T) {
	workerPool := pool.NewPool(10, 200)
	defer func() { _ = workerPool.Shutdown(5 * time.Second) }()

	ctxManager := agent.NewContextManager()
	defer ctxManager.Shutdown()

	registry := NewRegistry()
	handler := &IntegrationMockHandler{
		name:           "scale_handler",
		commands:       []string{"scale_cmd"},
		executionDelay: 1 * time.Millisecond, // Small delay to simulate work
	}
	_ = registry.Register(handler)

	h, _ := registry.Get("scale_cmd")
	args := &common.CommandArgs{}

	// Test with different concurrency levels
	concurrencyLevels := []int{1, 5, 10}

	for _, concurrency := range concurrencyLevels {
		taskCount := 100
		var wg sync.WaitGroup
		var completed int32

		start := time.Now()

		for i := 0; i < taskCount; i++ {
			wg.Add(1)
			ctx, cancel := ctxManager.NewContext(5 * time.Second)

			err := workerPool.Submit(ctx, func() error {
				defer wg.Done()
				defer cancel()
				_, _, err := h.Execute(ctx, "scale_cmd", args)
				if err == nil {
					completed++
				}
				return err
			})

			if err != nil {
				wg.Done()
				cancel()
			}
		}

		wg.Wait()
		elapsed := time.Since(start)

		t.Logf("Concurrency %d: completed %d/%d tasks in %v (%.2f tasks/sec)",
			concurrency, completed, taskCount, elapsed, float64(completed)/elapsed.Seconds())
	}
}

// TestPerformance_RegistryLookupSpeed tests registry lookup performance
func TestPerformance_RegistryLookupSpeed(t *testing.T) {
	registry := NewRegistry()

	// Register many handlers
	for i := 0; i < 100; i++ {
		handler := &MockHandler{
			name:     "handler" + string(rune(i)),
			commands: []string{"cmd" + string(rune(i))},
		}
		_ = registry.Register(handler)
	}

	// Warm up
	for i := 0; i < 10; i++ {
		_, _ = registry.Get("cmd" + string(rune(50)))
	}

	// Measure lookup time
	iterations := 10000
	start := time.Now()

	for i := 0; i < iterations; i++ {
		cmdIdx := i % 100
		_, _ = registry.Get("cmd" + string(rune(cmdIdx)))
	}

	elapsed := time.Since(start)
	avgLookup := elapsed / time.Duration(iterations)

	t.Logf("Average registry lookup: %v (total: %v for %d lookups)", avgLookup, elapsed, iterations)

	// Lookup should be very fast (< 100µs)
	if avgLookup > 100*time.Microsecond {
		t.Errorf("Average lookup time %v exceeds 100µs limit", avgLookup)
	}

	registry.Clear()
}

// TestPerformance_GoroutineLimit verifies goroutine limits are enforced
func TestPerformance_GoroutineLimit(t *testing.T) {
	maxWorkers := 10
	workerPool := pool.NewPool(maxWorkers, 100)
	defer func() { _ = workerPool.Shutdown(5 * time.Second) }()

	ctx := context.Background()

	// Track concurrent goroutines
	var maxConcurrent int32
	var current int32
	var mu sync.Mutex

	// Submit tasks that take some time
	var wg sync.WaitGroup
	taskCount := 50

	for i := 0; i < taskCount; i++ {
		wg.Add(1)
		err := workerPool.Submit(ctx, func() error {
			defer wg.Done()

			mu.Lock()
			current++
			if current > maxConcurrent {
				maxConcurrent = current
			}
			mu.Unlock()

			time.Sleep(20 * time.Millisecond)

			mu.Lock()
			current--
			mu.Unlock()

			return nil
		})
		if err != nil {
			wg.Done()
		}
	}

	wg.Wait()

	t.Logf("Max concurrent goroutines: %d (limit: %d)", maxConcurrent, maxWorkers)

	if int(maxConcurrent) > maxWorkers {
		t.Errorf("Max concurrent goroutines %d exceeded worker limit %d", maxConcurrent, maxWorkers)
	}
}

// TestPerformance_ContextCancellationSpeed tests context cancellation overhead
func TestPerformance_ContextCancellationSpeed(t *testing.T) {
	ctxManager := agent.NewContextManager()
	defer ctxManager.Shutdown()

	// Measure context creation and cancellation
	iterations := 1000
	start := time.Now()

	for i := 0; i < iterations; i++ {
		ctx, cancel := ctxManager.NewContext(5 * time.Second)
		_ = ctx
		cancel()
	}

	elapsed := time.Since(start)
	avgTime := elapsed / time.Duration(iterations)

	t.Logf("Average context create/cancel: %v (total: %v for %d iterations)", avgTime, elapsed, iterations)

	// Context operations should be fast (< 100µs)
	if avgTime > 100*time.Microsecond {
		t.Errorf("Average context operation time %v exceeds 100µs limit", avgTime)
	}
}
