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

func (rq *RequestQueue) request(method, url string, data interface{}, priority int, due time.Time) {
	// time.Time{}: 0001-01-01 00:00:00 +0000 UTC
	if due.IsZero() {
		due = time.Now()
	}

	entry := PriorityEntry{
		priority: priority,
		method:   method,
		url:      url,
		data:     data,
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
	rq.request(http.MethodPost, url, data, priority, due)
}

func (rq *RequestQueue) Patch(url string, data interface{}, priority int, due time.Time) {
	rq.request(http.MethodPatch, url, data, priority, due)
}

func (rq *RequestQueue) Put(url string, data interface{}, priority int, due time.Time) {
	rq.request(http.MethodPut, url, data, priority, due)
}

func (rq *RequestQueue) Delete(url string, data interface{}, priority int, due time.Time) {
	rq.request(http.MethodDelete, url, data, priority, due)
}
