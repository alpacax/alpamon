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

func getOne(t *testing.T) PriorityEntry {
	t.Helper()
	Rqueue.cond.L.Lock()
	defer Rqueue.cond.L.Unlock()
	entry, err := Rqueue.queue.Get()
	require.NoError(t, err, "drain")
	return entry
}

func drainOne(t *testing.T) {
	t.Helper()
	getOne(t)
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
		assert.Len(t, remaining.data, 4096)
	}

	got, err = queue.Get()
	require.NoError(t, err)
	assert.Equal(t, "/b", got.url)

	got, err = queue.Get()
	require.NoError(t, err)
	assert.Equal(t, "/c", got.url)
}

func TestPostChunk_GivenCtxWithNoDeadline_WhenBelowHighWater_ThenEnqueuedWithZeroExpiry(t *testing.T) {
	newRequestQueue()

	Rqueue.postChunk(context.Background(), "/chunk", nil, 10, 5, time.Millisecond, time.Second)

	assert.Equal(t, 1, queueSize(), "expected chunk enqueued")
	entry := getOne(t)
	assert.True(t, entry.expiry.IsZero(), "no ctx deadline means no expiry should be stamped")
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

	assert.Equal(t, 3, queueSize(), "cancelled chunk should be dropped")
}

// A chunk's expiry is derived from its ctx's deadline, so a reporter stops
// delivering it chunkDeliveryGrace after the command that produced it was killed.

func TestPostChunk_GivenCtxWithDeadline_WhenEnqueued_ThenExpiryIsDeadlinePlusGrace(t *testing.T) {
	newRequestQueue()

	deadline := time.Now().Add(10 * time.Second)
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()

	Rqueue.postChunk(ctx, "/chunk", nil, 10, 5, time.Millisecond, time.Second)

	entry := getOne(t)
	assert.WithinDuration(t, deadline.Add(chunkDeliveryGrace), entry.expiry, time.Second,
		"chunk expiry should be the ctx deadline plus the delivery grace window")
}

func TestPostChunk_GivenCtxAlreadyPastDeadline_WhenQueueHasRoom_ThenChunkStillEnqueuedWithGraceExpiry(t *testing.T) {
	newRequestQueue()

	deadline := time.Now().Add(-time.Minute)
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	require.Error(t, ctx.Err(), "test setup: ctx must already be expired")

	Rqueue.postChunk(ctx, "/chunk", nil, 10, 5, time.Millisecond, time.Second)

	require.Equal(t, 1, queueSize(), "the fast path must enqueue regardless of ctx.Err(); expiry, not ctx, bounds delivery")
	entry := getOne(t)
	assert.WithinDuration(t, deadline.Add(chunkDeliveryGrace), entry.expiry, time.Second,
		"expiry should still be the deadline plus the delivery grace window")
}

func TestPost_GivenNonChunkEntry_WhenEnqueued_ThenExpiryStaysZero(t *testing.T) {
	newRequestQueue()

	Rqueue.Post("/fin", nil, 11, time.Time{})
	entry := getOne(t)
	assert.True(t, entry.expiry.IsZero(), "Post must not stamp an expiry")

	Rqueue.PostWithHeaders("/fin", nil, 11, time.Time{}, Headers{"X-Test": "1"})
	entry = getOne(t)
	assert.True(t, entry.expiry.IsZero(), "PostWithHeaders must not stamp an expiry")
}
