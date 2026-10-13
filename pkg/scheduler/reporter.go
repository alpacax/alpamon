package scheduler

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"sync"
	"time"

	"github.com/alpacax/alpamon/v2/pkg/agent"
	"github.com/alpacax/alpamon/v2/pkg/config"
	"github.com/alpacax/alpamon/v2/pkg/utils"
	"github.com/alpacax/alpamon/v2/pkg/version"
	"github.com/rs/zerolog/log"
)

const (
	startUpEventURL = "/api/events/events/"
	// maxRetryAfter caps a server's Retry-After so one bogus value cannot park a retry for days.
	maxRetryAfter = 5 * time.Minute
)

func NewReporter(index int, session *Session) *Reporter {
	return &Reporter{
		name:    fmt.Sprintf("Reporter-%d", index),
		session: session,
	}
}

func StartReporters(session *Session, ctxManager *agent.ContextManager) *ReporterManager {
	newRequestQueue() // init RequestQueue

	wg := &sync.WaitGroup{}
	cancels := make([]func(), 0, config.GlobalSettings.HTTPThreads)

	for i := 0; i < config.GlobalSettings.HTTPThreads; i++ {
		wg.Add(1)
		reporter := NewReporter(i, session)
		// Create context for each reporter with no timeout
		ctx, cancel := ctxManager.NewContext(0)
		cancels = append(cancels, cancel)
		go func(ctx context.Context) {
			defer wg.Done()
			reporter.Run(ctx)
		}(ctx)
	}

	reportStartupEvent()

	return &ReporterManager{
		wg:      wg,
		cancels: cancels,
	}
}

// Shutdown gracefully stops all reporters with a timeout
func (rm *ReporterManager) Shutdown(timeout time.Duration) error {
	log.Info().Msg("Shutting down reporters...")

	// Cancel all reporter contexts
	for _, cancel := range rm.cancels {
		cancel()
	}

	// Under the lock, so a reporter between its ctx check and cond.Wait cannot miss it.
	broadcastQueue()

	// Wait for all reporters to finish with timeout
	done := make(chan struct{})
	go func() {
		rm.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		log.Info().Msg("All reporters shut down gracefully")
		return nil
	case <-time.After(timeout):
		return fmt.Errorf("reporter shutdown timeout after %v", timeout)
	}
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
	var headers Headers
	if entry.headers != nil {
		headers = *entry.headers
	}
	resp, statusCode, respHeader, err := r.session.RequestWithHeaders(entry.method, entry.url, entry.data, 5, headers)

	var success bool
	if err != nil {
		log.Error().Err(err).Msgf("%s %s", entry.method, entry.url)
		success = false
	} else if utils.IsSuccessStatusCode(statusCode) {
		success = true
	} else {
		if statusCode == http.StatusBadRequest {
			log.Error().Err(err).Msgf("%s %s: %d Bad Request: %s", entry.method, entry.url, statusCode, resp)
		} else {
			log.Error().Msgf("%s %s: %d %s.", entry.method, entry.url, statusCode, resp)
		}
		success = false
	}

	if success {
		return
	}
	if entry.retry > 0 && isRetryable(statusCode) {
		now := time.Now()
		backoff := time.Duration(math.Pow(2, float64(RetryLimit-entry.retry))) * time.Second
		if statusCode == http.StatusTooManyRequests || statusCode == http.StatusServiceUnavailable {
			backoff = max(backoff, utils.ParseRetryAfter(respHeader.Get("Retry-After"), now, maxRetryAfter))
		}
		entry.due = now.Add(backoff)
		entry.retry--
		if err = Rqueue.Requeue(entry); err != nil {
			log.Error().Err(err).Msgf("Dropping retry of %s %s", entry.method, entry.url)
		}
	}
}

// isRetryable reports whether a failed request can succeed on a later try.
// 403 stays retryable: an edge rate limit may answer it, and a real denial
// costs at most RetryLimit spaced attempts.
func isRetryable(statusCode int) bool {
	switch statusCode {
	case http.StatusBadRequest, http.StatusUnauthorized, http.StatusNotFound:
		return false
	}
	return true
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

// waitForEntry waits for a due entry from the queue or context cancellation
func (r *Reporter) waitForEntry(ctx context.Context) (PriorityEntry, bool) {
	Rqueue.cond.L.Lock()
	defer Rqueue.cond.L.Unlock()

	for {
		select {
		case <-ctx.Done():
			log.Debug().Msgf("Reporter %s shutting down", r.name)
			return PriorityEntry{}, false
		default:
		}

		entry, wait, ok := Rqueue.queue.Next(time.Now())
		if ok {
			return entry, true
		}
		if wait <= 0 {
			Rqueue.cond.Wait()
			continue
		}

		// Only backing-off entries remain: wait on cond so an enqueue or shutdown still wakes us.
		timer := time.AfterFunc(wait, broadcastQueue)
		Rqueue.cond.Wait()
		timer.Stop()
	}
}

func broadcastQueue() {
	Rqueue.cond.L.Lock()
	Rqueue.cond.Broadcast()
	Rqueue.cond.L.Unlock()
}

// processEntry handles the business logic for a queue entry
func (r *Reporter) processEntry(entry PriorityEntry) {
	// Handle expired entries
	if !entry.expiry.IsZero() && entry.expiry.Before(time.Now()) {
		return
	}

	// Process the entry
	r.query(entry)
}
