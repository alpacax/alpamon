package agent

import (
	"sync"
	"time"
)

// ShutdownWaitBudget bounds a join a context-unaware check could hang forever.
// Scheduler and collector each spend it, so shutdown can take twice it.
const ShutdownWaitBudget = 5 * time.Second

// WaitWithTimeout abandons its goroutine on timeout, leaving it on wg.Wait for good.
func WaitWithTimeout(wg *sync.WaitGroup, timeout time.Duration) bool {
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		return true
	case <-time.After(timeout):
		return false
	}
}
