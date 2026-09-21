package agent

import (
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWaitWithTimeout_ReturnsTrueWhenTheWaitGroupFinishesBeforeTheTimeout(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var wg sync.WaitGroup
		wg.Go(func() { time.Sleep(10 * time.Millisecond) })

		result := WaitWithTimeout(&wg, time.Second)

		require.True(t, result, "WaitWithTimeout should return true when the goroutine finishes before the timeout")
	})
}

func TestWaitWithTimeout_ReturnsFalseWhenTheGoroutineNeverFinishes(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var wg sync.WaitGroup
		wg.Add(1)

		result := WaitWithTimeout(&wg, 10*time.Millisecond)

		assert.False(t, result, "WaitWithTimeout should return false once the timeout elapses")

		// WaitWithTimeout leaves its goroutine blocked on wg.Wait, and the bubble
		// panics on exit while one is still blocked.
		wg.Done()
		synctest.Wait()
	})
}

func TestWaitWithTimeout_ReturnsTrueImmediatelyWhenTheWaitGroupIsAlreadyZero(t *testing.T) {
	var wg sync.WaitGroup

	start := time.Now()
	result := WaitWithTimeout(&wg, time.Second)
	elapsed := time.Since(start)

	require.True(t, result, "WaitWithTimeout should return true for an already-zero WaitGroup")
	assert.Less(t, elapsed, 100*time.Millisecond, "an already-zero WaitGroup should not wait for the timeout")
}
