package scheduler

import (
	"context"
	"testing"
	"time"
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
	for i := 0; i < n; i++ {
		Rqueue.Post("/other", nil, 10, time.Time{})
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
	newRequestQueue()
	fill(3) // at the high-water mark

	done := make(chan struct{})
	go func() {
		Rqueue.postChunk(context.Background(), "/chunk", nil, 10, 3, time.Millisecond, time.Second)
		close(done)
	}()

	select {
	case <-done:
		t.Fatal("postChunk returned at high-water; expected backpressure")
	case <-time.After(50 * time.Millisecond):
	}

	drainOne(t) // drop below high-water

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("postChunk did not return after space freed")
	}
}

func TestPostChunk_DropsAfterMaxWait(t *testing.T) {
	newRequestQueue()
	fill(3)

	start := time.Now()
	Rqueue.postChunk(context.Background(), "/chunk", nil, 10, 3, time.Millisecond, 30*time.Millisecond)

	if elapsed := time.Since(start); elapsed < 30*time.Millisecond {
		t.Errorf("expected to wait ~maxWait before dropping, waited %v", elapsed)
	}
	if got := queueSize(); got != 3 {
		t.Errorf("chunk should be dropped under sustained pressure, size got %d want 3", got)
	}
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
