package scheduler

import (
	"net/http"
	"sync"
	"time"

	"github.com/adrianbrad/queue"
	"github.com/rs/zerolog/log"
)

var (
	Rqueue *RequestQueue
)

const (
	RetryLimit   = 5
	MaxQueueSize = 10 * 60 * 60 // 10 entries/second * 1h
)

func newRequestQueue() {
	Rqueue = &RequestQueue{
		queue: queue.NewPriority(
			[]PriorityEntry{},
			lessFunc,
			queue.WithCapacity(MaxQueueSize),
		),
		cond: sync.NewCond(&sync.Mutex{}),
	}
}

// less function of PriorityQueue
func lessFunc(elem, otherElem PriorityEntry) bool {
	if elem.priority == otherElem.priority {
		return elem.due.Before(otherElem.due) // elem.Due < otherElem.Due
	}
	return elem.priority < otherElem.priority
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
