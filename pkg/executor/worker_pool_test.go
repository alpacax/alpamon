package executor

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/alpacax/alpamon/v2/internal/pool"
	"github.com/alpacax/alpamon/v2/pkg/agent"
	"github.com/alpacax/alpamon/v2/pkg/executor/handlers/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestWorkerPool_SpreadsCommandsAcrossWorkers pins that workers actually divide the
// work. Each task occupies a worker for jobTime, so a pool of n workers clears
// the queue in taskCount/n batches—an exact figure on the bubble's clock, which
// a pool that serialized its jobs could not produce.
func TestWorkerPool_SpreadsCommandsAcrossWorkers(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const (
			taskCount = 100
			jobTime   = 1 * time.Millisecond
		)

		for _, workers := range []int{1, 5, 10} {
			workerPool := pool.NewPool(workers, taskCount)
			ctxManager := agent.NewContextManager()

			registry := NewRegistry()
			handler := &IntegrationMockHandler{
				name:           "scale_handler",
				commands:       []string{"scale_cmd"},
				executionDelay: jobTime,
			}
			require.NoError(t, registry.Register(handler), "workers=%d: register failed", workers)

			h, err := registry.Get("scale_cmd")
			require.NoError(t, err, "workers=%d: the handler must be reachable", workers)
			args := &common.CommandArgs{}

			var wg sync.WaitGroup
			var completed atomic.Int32

			start := time.Now()

			for range taskCount {
				wg.Add(1)
				ctx, cancel := ctxManager.NewContext(5 * time.Second)

				submitErr := workerPool.Submit(ctx, func() error {
					defer wg.Done()
					defer cancel()
					_, _, err := h.Execute(ctx, "scale_cmd", args)
					if err == nil {
						completed.Add(1)
					}
					return err
				})

				if submitErr != nil {
					wg.Done()
					cancel()
					assert.Failf(t, "submit failed", "workers=%d: %v", workers, submitErr)
				}
			}

			wg.Wait()

			assert.Equal(t, int32(taskCount), completed.Load(), "workers=%d: not every task ran", workers)
			assert.Equal(t, time.Duration(taskCount/workers)*jobTime, time.Since(start),
				"workers=%d: the pool did not spread the tasks across its workers", workers)

			require.NoError(t, workerPool.Shutdown(5*time.Second), "workers=%d: shutdown failed", workers)
			ctxManager.Shutdown()
		}
	})
}

// TestWorkerPool_SaturatesWithoutExceedingWorkers verifies the pool runs exactly as many jobs at
// once as it has workers—never more, and never fewer once enough work is queued
// to occupy them all.
func TestWorkerPool_SaturatesWithoutExceedingWorkers(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const (
			maxWorkers = 10
			taskCount  = 50
		)

		workerPool := pool.NewPool(maxWorkers, taskCount)
		defer func() { assert.NoError(t, workerPool.Shutdown(5*time.Second), "shutdown failed") }()

		ctx := context.Background()

		// Track concurrent goroutines
		var maxConcurrent int
		var current int
		var mu sync.Mutex

		// Submit tasks that take some time
		var wg sync.WaitGroup

		for range taskCount {
			wg.Add(1)
			err := workerPool.Submit(ctx, func() error {
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
			if err != nil {
				wg.Done()
				assert.Failf(t, "submit failed", "%v", err)
			}
		}

		wg.Wait()

		assert.Equal(t, maxWorkers, maxConcurrent, "the pool must saturate its workers, and never exceed them")
	})
}
