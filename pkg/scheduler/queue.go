package scheduler

import (
	"container/heap"
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

// priorityQueue is a thread-safe bounded priority queue backed by container/heap.
type priorityQueue struct {
	mu       sync.Mutex
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
	pq.mu.Lock()
	defer pq.mu.Unlock()
	if pq.capacity > 0 && pq.h.Len() >= pq.capacity {
		return errQueueFull
	}
	heap.Push(&pq.h, entry)
	return nil
}

func (pq *priorityQueue) Get() (PriorityEntry, error) {
	pq.mu.Lock()
	defer pq.mu.Unlock()
	if pq.h.Len() == 0 {
		return PriorityEntry{}, errors.New("queue is empty")
	}
	return heap.Pop(&pq.h).(PriorityEntry), nil
}

func (pq *priorityQueue) Size() int {
	pq.mu.Lock()
	defer pq.mu.Unlock()
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

	// Do not wake reporter goroutine if the queue is full or uninitialized.
	err := rq.queue.Offer(entry)
	if err != nil {
		log.Error().Err(err).Msgf("Queue is full or uninitialized, dropping entry: %s", entry.url)
		return
	}

	rq.cond.Signal()
}

func (rq *RequestQueue) Post(url string, data interface{}, priority int, due time.Time) {
	rq.request(http.MethodPost, url, data, priority, due, nil)
}

func (rq *RequestQueue) PostWithHeaders(url string, data interface{}, priority int, due time.Time, headers Headers) {
	rq.request(http.MethodPost, url, data, priority, due, headers)
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
