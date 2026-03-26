package scheduler

import (
	"github.com/adrianbrad/queue"
	"net/http"
	"sync"
	"time"
)

type Session struct {
	BaseURL       string
	Client        *http.Client
	Authorization string
}

// Headers is a named map type for HTTP headers attached to queue entries.
type Headers map[string]string

// queue //
type PriorityEntry struct {
	priority int
	method   string
	url      string
	data     interface{}
	headers  *Headers
	due      time.Time
	expiry   time.Time
	retry    int
}

type RequestQueue struct {
	queue *queue.Priority[PriorityEntry]
	cond  *sync.Cond
}

// reporter //
type Reporter struct {
	name     string
	session  *Session
	counters *counters
}

type counters struct {
	success int
	failure int
	ignored int
	delay   float64
	latency float64
}

// ReporterManager manages the lifecycle of multiple reporter goroutines
type ReporterManager struct {
	wg      *sync.WaitGroup
	cancels []func()
}
