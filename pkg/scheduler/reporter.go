package scheduler

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"sync"
	"time"

	"github.com/alpacax/alpamon/pkg/agent"
	"github.com/alpacax/alpamon/pkg/config"
	"github.com/alpacax/alpamon/pkg/utils"
	"github.com/alpacax/alpamon/pkg/version"
	"github.com/rs/zerolog/log"
)

const (
	startUpEventURL = "/api/events/events/"
)

func NewReporter(index int, session *Session) *Reporter {
	return &Reporter{
		name:    fmt.Sprintf("Reporter-%d", index),
		session: session,
		counters: &counters{
			success: 0,
			failure: 0,
			ignored: 0,
			delay:   0.0,
			latency: 0.0,
		},
	}
}

func StartReporters(session *Session, ctxManager *agent.ContextManager) {
	newRequestQueue() // init RequestQueue

	wg := sync.WaitGroup{}
	for i := 0; i < config.GlobalSettings.HTTPThreads; i++ {
		wg.Add(1)
		reporter := NewReporter(i, session)
		// Create context for each reporter with no timeout
		ctx, _ := ctxManager.NewContext(0)
		go func(ctx context.Context) {
			defer wg.Done()
			reporter.Run(ctx)
		}(ctx)
	}

	reportStartupEvent()
}

func reportStartupEvent() {
	eventData, _ := json.Marshal(map[string]string{
		"reporter":    "alpamon",
		"record":      "started",
		"description": fmt.Sprintf("alpamon %s started running.", version.Version),
	})

	Rqueue.Post(startUpEventURL, eventData, 10, time.Time{})
}

func (r *Reporter) query(entry PriorityEntry) {
	t1 := time.Now()
	resp, statusCode, err := r.session.Request(entry.method, entry.url, entry.data, 5)
	t2 := time.Now()

	r.counters.delay = r.counters.delay*0.9 + (t2.Sub(entry.due).Seconds())*0.1
	r.counters.latency = r.counters.latency*0.9 + (t2.Sub(t1).Seconds())*0.1

	var success bool
	if err != nil {
		log.Error().Err(err).Msgf("%s %s", entry.method, entry.url)
		success = false
	} else if utils.IsSuccessStatusCode(statusCode) {
		success = true
	} else {
		if statusCode == http.StatusBadRequest {
			log.Error().Err(err).Msgf("%d Bad Request: %s", statusCode, resp)
		} else {
			log.Error().Msgf("%s %s: %d %s.", entry.method, entry.url, statusCode, resp)
		}
		success = false
	}

	if success {
		r.counters.success++
	} else {
		r.counters.failure++
		if entry.retry > 0 {
			backoff := time.Duration(math.Pow(2, float64(RetryLimit-entry.retry))) * time.Second
			entry.due = entry.due.Add(backoff)
			entry.retry--
			err = Rqueue.queue.Offer(entry)
			if err != nil {
				r.counters.ignored++
			}
		} else {
			r.counters.ignored++
		}
	}
}

func (r *Reporter) Run(ctx context.Context) {
	for {
		// Check for shutdown signal
		select {
		case <-ctx.Done():
			log.Debug().Msgf("Reporter %s shutting down", r.name)
			return
		default:
		}

		// Wait for queue entry
		entry, ok := r.waitForEntry(ctx)
		if !ok {
			return // Context cancelled during wait
		}

		// Process the entry
		r.processEntry(entry)
	}
}

// waitForEntry waits for an entry from the queue or context cancellation
func (r *Reporter) waitForEntry(ctx context.Context) (PriorityEntry, bool) {
	Rqueue.cond.L.Lock()
	defer Rqueue.cond.L.Unlock()

	for Rqueue.queue.Size() == 0 {
		// Check context before waiting
		select {
		case <-ctx.Done():
			log.Debug().Msgf("Reporter %s shutting down", r.name)
			return PriorityEntry{}, false
		default:
		}
		Rqueue.cond.Wait()
	}

	entry, err := Rqueue.queue.Get()
	if err != nil {
		// Return empty entry to continue loop
		return PriorityEntry{}, true
	}

	return entry, true
}

// processEntry handles the business logic for a queue entry
func (r *Reporter) processEntry(entry PriorityEntry) {
	// Handle expired entries
	if !entry.expiry.IsZero() && entry.expiry.Before(time.Now()) {
		r.counters.ignored++
		return
	}

	// Handle entries that are not yet due
	if !entry.due.IsZero() && entry.due.After(time.Now()) {
		err := Rqueue.queue.Offer(entry)
		if err != nil {
			r.counters.ignored++
		}
		time.Sleep(1 * time.Second)
		return
	}

	// Process the entry
	r.query(entry)
}
