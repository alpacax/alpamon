package scheduler

import (
	"container/heap"
	"context"
	"errors"
	"net/http"
	"sync"
	"time"

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
	*h = old[:n-1]
	return item
}

// priorityQueue is a bounded priority queue backed by container/heap.
// NOT thread-safe: callers must hold RequestQueue.cond.L for all operations.
type priorityQueue struct {
	h        priorityHeap
	capacity int
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
	if pq.capacity > 0 && pq.h.Len() >= pq.capacity {
		return errQueueFull
	}
	heap.Push(&pq.h, entry)
	return nil
}

func (pq *priorityQueue) Get() (PriorityEntry, error) {
	if pq.h.Len() == 0 {
		return PriorityEntry{}, errors.New("queue is empty")
	}
	return heap.Pop(&pq.h).(PriorityEntry), nil
}

func (pq *priorityQueue) Size() int {
	return pq.h.Len()
}

func newRequestQueue() {
	Rqueue = &RequestQueue{
		queue: newPriorityQueue(MaxQueueSize),
		cond:  sync.NewCond(&sync.Mutex{}),
	}
}

func (rq *RequestQueue) request(method, url string, data interface{}, priority int, due time.Time, headers Headers) {
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
		// expiry:
		retry: RetryLimit,
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

func (rq *RequestQueue) Post(url string, data interface{}, priority int, due time.Time) {
	rq.request(http.MethodPost, url, data, priority, due, nil)
}

func (rq *RequestQueue) PostWithHeaders(url string, data interface{}, priority int, due time.Time, headers Headers) {
	rq.request(http.MethodPost, url, data, priority, due, headers)
}

// PostChunk enqueues a chunk, throttling the command while the queue is full and dropping past ctx/maxWait.
func (rq *RequestQueue) PostChunk(ctx context.Context, url string, data interface{}, priority int) {
	rq.postChunk(ctx, url, data, priority, chunkQueueHighWater, chunkBackpressurePoll, chunkBackpressureMaxWait)
}

func (rq *RequestQueue) postChunk(ctx context.Context, url string, data interface{}, priority, highWater int, poll, maxWait time.Duration) {
	start := time.Now()
	for {
		rq.cond.L.Lock()
		size := rq.queue.Size()
		rq.cond.L.Unlock()

		if size < highWater {
			rq.Post(url, data, priority, time.Time{})
			return
		}
		if ctx.Err() != nil || time.Since(start) >= maxWait {
			log.Warn().Str("url", url).Msg("Chunk dropped under sustained backpressure")
			return
		}
		select {
		case <-ctx.Done():
		case <-time.After(poll):
		}
	}
}

func (rq *RequestQueue) Patch(url string, data interface{}, priority int, due time.Time) {
	rq.request(http.MethodPatch, url, data, priority, due, nil)
}

func (rq *RequestQueue) PatchWithHeaders(url string, data interface{}, priority int, due time.Time, headers Headers) {
	rq.request(http.MethodPatch, url, data, priority, due, headers)
}

func (rq *RequestQueue) Put(url string, data interface{}, priority int, due time.Time) {
	rq.request(http.MethodPut, url, data, priority, due, nil)
}

func (rq *RequestQueue) Delete(url string, data interface{}, priority int, due time.Time) {
	rq.request(http.MethodDelete, url, data, priority, due, nil)
}

func (rq *RequestQueue) DeleteWithHeaders(url string, data interface{}, priority int, due time.Time, headers Headers) {
	rq.request(http.MethodDelete, url, data, priority, due, headers)
}
