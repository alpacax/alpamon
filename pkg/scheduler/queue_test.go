package scheduler

import (
	"context"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func queueSize() int {
	Rqueue.cond.L.Lock()
	defer Rqueue.cond.L.Unlock()
	return Rqueue.queue.Size()
}

func drainOne(t *testing.T) {
	t.Helper()
	Rqueue.cond.L.Lock()
	defer Rqueue.cond.L.Unlock()
	if _, err := Rqueue.queue.Get(); err != nil {
		t.Fatalf("drain: %v", err)
	}
}

func fill(n int) {
	for range n {
		Rqueue.Post("/other", nil, 10, time.Time{})
	}
}

func TestPriorityQueue_GetReleasesOnlyRemovedEntry(t *testing.T) {
	queue := newPriorityQueue(3)
	headers := Headers{"X-Test": "value"}
	entries := []PriorityEntry{
		{priority: 3, url: "/c", data: make([]byte, 4096), headers: &headers},
		{priority: 1, url: "/a", data: make([]byte, 4096), headers: &headers},
		{priority: 2, url: "/b", data: make([]byte, 4096), headers: &headers},
	}
	for _, e := range entries {
		require.NoError(t, queue.Offer(e))
	}

	vacated := len(queue.h) - 1
	got, err := queue.Get()
	require.NoError(t, err)
	assert.Equal(t, "/a", got.url)

	assert.Len(t, queue.h, 2)
	assert.Equal(t, PriorityEntry{}, queue.h[:cap(queue.h)][vacated])
	for _, remaining := range queue.h {
		assert.NotEqual(t, PriorityEntry{}, remaining)
		assert.Len(t, remaining.data, 4096)
	}
}

func TestPostChunk_EnqueuesBelowHighWater(t *testing.T) {
	newRequestQueue()

	Rqueue.postChunk(context.Background(), "/chunk", nil, 10, 5, time.Millisecond, time.Second)

	if got := queueSize(); got != 1 {
		t.Fatalf("expected chunk enqueued, size got %d want 1", got)
	}
}

func TestPostChunk_BlocksUntilSpaceFrees(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		newRequestQueue()
		fill(3) // at the high-water mark

		done := make(chan struct{})
		go func() {
			Rqueue.postChunk(context.Background(), "/chunk", nil, 10, 3, time.Millisecond, time.Second)
			close(done)
		}()

		// Wait returns once postChunk parks on its poll timer, proving it reached the backpressure loop.
		synctest.Wait()
		select {
		case <-done:
			t.Fatal("postChunk returned at high-water; expected backpressure")
		default:
		}

		drainOne(t) // drop below high-water

		select {
		case <-done:
		// Longer than postChunk's own maxWait: at the same duration the two would tie, and the select would break it arbitrarily.
		case <-time.After(5 * time.Second):
			t.Fatal("postChunk did not return after space freed")
		}
	})
}

func TestPostChunk_DropsAfterMaxWait(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		newRequestQueue()
		fill(3)

		start := time.Now()
		Rqueue.postChunk(context.Background(), "/chunk", nil, 10, 3, time.Millisecond, 30*time.Millisecond)

		assert.Equal(t, 30*time.Millisecond, time.Since(start), "expected to wait exactly maxWait before dropping")
		assert.Equal(t, 3, queueSize(), "chunk should be dropped under sustained pressure")
	})
}

func TestPostChunk_DropsOnContextCancel(t *testing.T) {
	newRequestQueue()
	fill(3)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	Rqueue.postChunk(ctx, "/chunk", nil, 10, 3, time.Millisecond, time.Second)

	if got := queueSize(); got != 3 {
		t.Errorf("cancelled chunk should be dropped, size got %d want 3", got)
	}
}
