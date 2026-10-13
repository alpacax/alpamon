package scheduler

import (
	"container/heap"
	"context"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/alpacax/alpamon/v2/internal/protocol"
	"github.com/rs/zerolog/log"
)

var (
	Rqueue *RequestQueue
)

const (
	RetryLimit   = 5
	MaxQueueSize = 10 * 60 * 60 // 10 entries/second * 1h

	// chunkQueueHighWater is the depth at which chunks back off, reserving slots for other telemetry.
	chunkQueueHighWater = MaxQueueSize * 8 / 10
	// chunkQueueMaxBytes holds queued chunk data to what the high-water mark held at 4 KiB per chunk.
	chunkQueueMaxBytes = chunkQueueHighWater * 4 * 1024
	// chunkBackpressurePoll is how often a throttled chunk re-checks for room.
	chunkBackpressurePoll = 10 * time.Millisecond
	// chunkBackpressureMaxWait caps the throttle per chunk so sustained overload can't freeze a command.
	chunkBackpressureMaxWait = 2 * time.Second
)

var errQueueFull = errors.New("queue is full")

// priorityHeap implements heap.Interface for PriorityEntry.
type priorityHeap []PriorityEntry

func (h priorityHeap) Len() int { return len(h) }
func (h priorityHeap) Less(i, j int) bool {
	if h[i].priority == h[j].priority {
		return h[i].due.Before(h[j].due)
	}
	return h[i].priority < h[j].priority
}
func (h priorityHeap) Swap(i, j int) { h[i], h[j] = h[j], h[i] }

func (h *priorityHeap) Push(x any) {
	*h = append(*h, x.(PriorityEntry))
}

func (h *priorityHeap) Pop() any {
	old := *h
	n := len(old)
	item := old[n-1]
	// Clear the backing-array slot so processed request data can be reclaimed.
	old[n-1] = PriorityEntry{}
	*h = old[:n-1]
	return item
}

// dueHeap orders entries still backing off by when they become due.
type dueHeap []PriorityEntry

func (h dueHeap) Len() int           { return len(h) }
func (h dueHeap) Less(i, j int) bool { return h[i].due.Before(h[j].due) }
func (h dueHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }

func (h *dueHeap) Push(x any) {
	*h = append(*h, x.(PriorityEntry))
}

func (h *dueHeap) Pop() any {
	old := *h
	n := len(old)
	item := old[n-1]
	old[n-1] = PriorityEntry{}
	*h = old[:n-1]
	return item
}

// priorityQueue is a bounded priority queue backed by container/heap.
// Entries not yet due wait in a separate heap so they never sit ahead of a due entry.
// NOT thread-safe: callers must hold RequestQueue.cond.L for all operations.
type priorityQueue struct {
	h        priorityHeap
	waiting  dueHeap
	capacity int
	bytes    int // sum of size over queued entries
}

func newPriorityQueue(capacity int) *priorityQueue {
	pq := &priorityQueue{
		h:        make(priorityHeap, 0),
		capacity: capacity,
	}
	heap.Init(&pq.h)
	return pq
}

func (pq *priorityQueue) Offer(entry PriorityEntry) error {
	if pq.capacity > 0 && pq.Size() >= pq.capacity {
		return errQueueFull
	}
	pq.bytes += entry.size
	if !entry.due.IsZero() && entry.due.After(time.Now()) {
		heap.Push(&pq.waiting, entry)
		return nil
	}
	heap.Push(&pq.h, entry)
	return nil
}

// Next pops the best entry that is due at now. When none is, it reports how long until the soonest one is.
func (pq *priorityQueue) Next(now time.Time) (entry PriorityEntry, wait time.Duration, ok bool) {
	for pq.waiting.Len() > 0 && !pq.waiting[0].due.After(now) {
		heap.Push(&pq.h, heap.Pop(&pq.waiting))
	}
	if pq.h.Len() > 0 {
		return pq.take(heap.Pop(&pq.h)), 0, true
	}
	if pq.waiting.Len() > 0 {
		return PriorityEntry{}, pq.waiting[0].due.Sub(now), false
	}
	return PriorityEntry{}, 0, false
}

func (pq *priorityQueue) take(x any) PriorityEntry {
	entry := x.(PriorityEntry)
	pq.bytes -= entry.size
	return entry
}

func (pq *priorityQueue) Size() int {
	return pq.h.Len() + pq.waiting.Len()
}

func (pq *priorityQueue) Bytes() int {
	return pq.bytes
}

func newRequestQueue() {
	Rqueue = &RequestQueue{
		queue: newPriorityQueue(MaxQueueSize),
		cond:  sync.NewCond(&sync.Mutex{}),
	}
}

func (rq *RequestQueue) request(method, url string, data any, priority int, due time.Time, headers Headers) {
	rq.requestWithExpiry(method, url, data, 0, priority, due, time.Time{}, headers)
}

func (rq *RequestQueue) requestWithExpiry(method, url string, data any, size, priority int, due, expiry time.Time, headers Headers) {
	// time.Time{}: 0001-01-01 00:00:00 +0000 UTC
	if due.IsZero() {
		due = time.Now()
	}

	var h *Headers
	if len(headers) > 0 {
		h = &headers
	}

	entry := PriorityEntry{
		priority: priority,
		method:   method,
		url:      url,
		data:     data,
		headers:  h,
		due:      due,
		expiry:   expiry,
		retry:    RetryLimit,
		size:     size,
	}

	rq.cond.L.Lock()
	err := rq.queue.Offer(entry)
	if err == nil {
		rq.cond.Signal()
	}
	rq.cond.L.Unlock()

	if err != nil {
		log.Error().Err(err).Msgf("Queue is full or uninitialized, dropping entry: %s", entry.url)
		return
	}
}

// Requeue re-enqueues an entry under cond.L and signals waiting reporters.
func (rq *RequestQueue) Requeue(entry PriorityEntry) error {
	rq.cond.L.Lock()
	err := rq.queue.Offer(entry)
	if err == nil {
		rq.cond.Signal()
	}
	rq.cond.L.Unlock()
	return err
}

func (rq *RequestQueue) Post(url string, data any, priority int, due time.Time) {
	rq.request(http.MethodPost, url, data, priority, due, nil)
}

func (rq *RequestQueue) PostWithHeaders(url string, data any, priority int, due time.Time, headers Headers) {
	rq.request(http.MethodPost, url, data, priority, due, headers)
}

// PostChunk enqueues a chunk to be dropped past expiry, throttling the command while the queue is full in entries or chunk bytes.
// It drops the chunk on ctx cancellation or past maxWait; a ctx deadline alone keeps polling.
func (rq *RequestQueue) PostChunk(ctx context.Context, url string, chunk *protocol.CommandChunk, priority int, expiry time.Time) {
	rq.postChunk(ctx, url, chunk, len(chunk.Content), priority, expiry, chunkQueueHighWater, chunkQueueMaxBytes, chunkBackpressurePoll, chunkBackpressureMaxWait)
}

func (rq *RequestQueue) postChunk(ctx context.Context, url string, data any, size, priority int, expiry time.Time, highWater, maxBytes int, poll, maxWait time.Duration) {
	start := time.Now()

	for {
		rq.cond.L.Lock()
		room := rq.queue.Size() < highWater && rq.queue.Bytes()+size <= maxBytes
		rq.cond.L.Unlock()

		if room {
			// No ctx.Err() check: a timed-out command's final flush arrives past its deadline, and expiry bounds delivery instead.
			rq.requestWithExpiry(http.MethodPost, url, data, size, priority, time.Time{}, expiry, nil)
			return
		}
		if errors.Is(ctx.Err(), context.Canceled) || time.Since(start) >= maxWait {
			log.Warn().Str("url", url).Msg("Chunk dropped under sustained backpressure")
			return
		}
		done := ctx.Done()
		// Past its deadline Done() stays closed; selecting on it would busy-spin.
		if ctx.Err() != nil {
			done = nil
		}
		select {
		case <-done:
		case <-time.After(poll):
		}
	}
}

func (rq *RequestQueue) Patch(url string, data any, priority int, due time.Time) {
	rq.request(http.MethodPatch, url, data, priority, due, nil)
}

func (rq *RequestQueue) PatchWithHeaders(url string, data any, priority int, due time.Time, headers Headers) {
	rq.request(http.MethodPatch, url, data, priority, due, headers)
}

func (rq *RequestQueue) Put(url string, data any, priority int, due time.Time) {
	rq.request(http.MethodPut, url, data, priority, due, nil)
}

func (rq *RequestQueue) DeleteWithHeaders(url string, data any, priority int, due time.Time, headers Headers) {
	rq.request(http.MethodDelete, url, data, priority, due, headers)
}
