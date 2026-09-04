package executor

import (
	"fmt"
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
	const (
		taskCount = 100
		jobTime   = 1 * time.Millisecond
	)

	for _, workers := range []int{1, 5, 10} {
		t.Run(fmt.Sprintf("workers=%d", workers), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctxManager := agent.NewContextManager()
				defer ctxManager.Shutdown()

				// Both teardowns are deferred: run at the end of the body they never would,
				// because FailNow exits with the workers still alive and the bubble reports that.
				workerPool := pool.NewPool(workers, taskCount)
				defer func() {
					assert.NoError(t, workerPool.Shutdown(5*time.Second), "shutdown failed")
				}()

				registry := NewRegistry()
				handler := &IntegrationMockHandler{
					name:           "scale_handler",
					commands:       []string{"scale_cmd"},
					executionDelay: jobTime,
				}
				require.NoError(t, registry.Register(handler), "register failed")

				h, err := registry.Get("scale_cmd")
				require.NoError(t, err, "the handler must be reachable")
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

					require.NoError(t, submitErr, "submit failed")
				}

				wg.Wait()

				assert.Equal(t, int32(taskCount), completed.Load(), "not every task ran")
				assert.Equal(t, time.Duration(taskCount/workers)*jobTime, time.Since(start),
					"the pool did not spread the tasks across its workers")
			})
		})
	}
}
