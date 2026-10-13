package scheduler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/alpacax/alpamon/v2/pkg/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestReporter builds a Reporter wired to an httptest server through
// InitSession, mirroring how the real agent constructs its session.
func newTestReporter(t *testing.T, handler http.HandlerFunc) (*Reporter, *int32) {
	t.Helper()
	var hits int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		handler(w, r)
	}))
	t.Cleanup(server.Close)

	config.GlobalSettings = config.Settings{
		ServerURL: server.URL,
		SSLVerify: false,
		ID:        "test",
		Key:       "test",
	}

	session := InitSession()
	return NewReporter(0, session), &hits
}

func TestReporter_GivenChunkPastExpiryPlusGrace_WhenProcessed_ThenDroppedWithoutDelivering(t *testing.T) {
	reporter, hits := newTestReporter(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	entry := PriorityEntry{
		method: http.MethodPost,
		url:    "/chunk",
		data:   json.RawMessage(`{}`),
		due:    time.Now().Add(-time.Second),
		expiry: time.Now().Add(-time.Millisecond),
		retry:  RetryLimit,
	}

	reporter.processEntry(entry)

	assert.Equal(t, int32(0), atomic.LoadInt32(hits), "an expired chunk must never reach the server")
	assert.Equal(t, 1, reporter.counters.ignored, "expired chunk should be counted as ignored")
}

func TestReporter_GivenChunkQueuedBeforeDeadlineButDrainedWithinGrace_WhenProcessed_ThenDelivered(t *testing.T) {
	reporter, hits := newTestReporter(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// The command's deadline has already passed, but this entry is still
	// inside the chunkDeliveryGrace window: it must still be delivered.
	entry := PriorityEntry{
		method: http.MethodPost,
		url:    "/chunk",
		data:   json.RawMessage(`{}`),
		due:    time.Now().Add(-time.Second),
		expiry: time.Now().Add(time.Minute),
		retry:  RetryLimit,
	}

	reporter.processEntry(entry)

	assert.Equal(t, int32(1), atomic.LoadInt32(hits), "a chunk still within its grace window must be delivered")
	assert.Equal(t, 1, reporter.counters.success)
	assert.Equal(t, 0, reporter.counters.ignored)
}

func TestReporter_GivenRetryAfterFailure_WhenBackoffCrossesExpiry_ThenResurrectedEntryIsDropped(t *testing.T) {
	reporter, hits := newTestReporter(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	newRequestQueue()

	entry := PriorityEntry{
		method: http.MethodPost,
		url:    "/chunk",
		data:   json.RawMessage(`{}`),
		due:    time.Now().Add(-10 * time.Second),
		expiry: time.Now().Add(time.Minute),
		retry:  RetryLimit,
	}

	reporter.query(entry)
	require.Equal(t, int32(1), atomic.LoadInt32(hits), "first attempt should have reached the server")
	require.Equal(t, 1, queueSize(), "failed entry with retries left should be requeued")

	requeued := getOne(t)

	assert.Equal(t, entry.expiry, requeued.expiry, "requeue must carry the original expiry")

	requeued.expiry = time.Now().Add(-time.Millisecond) // stands in for the backoff wait outliving expiry
	reporter.processEntry(requeued)

	assert.Equal(t, int32(1), atomic.LoadInt32(hits), "retry/backoff must not resurrect a chunk past its expiry")
}

// Backoff was added to the entry's old due time, so on a backed-up queue it vanished.
func TestReporter_GivenFailureOnBackedUpQueue_WhenRequeued_ThenBackoffCountsFromNow(t *testing.T) {
	reporter, _ := newTestReporter(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	newRequestQueue()

	reporter.query(PriorityEntry{
		method: http.MethodPost,
		url:    "/chunk",
		data:   json.RawMessage(`{}`),
		due:    time.Now().Add(-10 * time.Second),
		retry:  RetryLimit,
	})

	require.Equal(t, 1, queueSize(), "a 500 should be requeued")
	assert.True(t, getOne(t).due.After(time.Now()), "the retry should wait, not fire at once")
}

// 400, 401 and 404 fail the same way on every retry.
func TestReporter_GivenNonRetryableStatus_WhenQueried_ThenNotRequeued(t *testing.T) {
	for _, status := range []int{http.StatusBadRequest, http.StatusUnauthorized, http.StatusNotFound} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			reporter, hits := newTestReporter(t, func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(status)
			})
			newRequestQueue()

			reporter.query(PriorityEntry{
				method: http.MethodPost,
				url:    "/chunk",
				data:   json.RawMessage(`{}`),
				due:    time.Now(),
				retry:  RetryLimit,
			})

			assert.Equal(t, int32(1), atomic.LoadInt32(hits), "the request should be sent once")
			assert.Zero(t, queueSize(), "a status that fails again must not be requeued")
			assert.Equal(t, 1, reporter.counters.ignored, "the dropped entry should be counted as ignored")
		})
	}
}

// A 429 carries the server's own wait, which the reporter ignored.
func TestReporter_Given429WithRetryAfter_WhenRequeued_ThenWaitsAtLeastRetryAfter(t *testing.T) {
	reporter, _ := newTestReporter(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "30")
		w.WriteHeader(http.StatusTooManyRequests)
	})
	newRequestQueue()

	reporter.query(PriorityEntry{
		method: http.MethodPost,
		url:    "/chunk",
		data:   json.RawMessage(`{}`),
		due:    time.Now(),
		retry:  RetryLimit,
	})

	require.Equal(t, 1, queueSize(), "a 429 should be requeued")
	assert.True(t, getOne(t).due.After(time.Now().Add(25*time.Second)), "the retry should wait for Retry-After")
}

// A 503 may carry Retry-After too (RFC 9110), and the reporter must wait for it.
func TestReporter_Given503WithRetryAfter_WhenRequeued_ThenWaitsAtLeastRetryAfter(t *testing.T) {
	reporter, _ := newTestReporter(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "30")
		w.WriteHeader(http.StatusServiceUnavailable)
	})
	newRequestQueue()

	reporter.query(PriorityEntry{
		method: http.MethodPost,
		url:    "/chunk",
		data:   json.RawMessage(`{}`),
		due:    time.Now(),
		retry:  RetryLimit,
	})

	require.Equal(t, 1, queueSize(), "a 503 should be requeued")
	assert.True(t, getOne(t).due.After(time.Now().Add(25*time.Second)), "the retry should wait for Retry-After")
}

// 403 stays retryable: an edge rate limit may answer it, so it must not be dropped like a 401.
func TestReporter_GivenForbidden_WhenQueried_ThenRequeuedWithBackoff(t *testing.T) {
	reporter, _ := newTestReporter(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	})
	newRequestQueue()

	reporter.query(PriorityEntry{
		method: http.MethodPost,
		url:    "/chunk",
		data:   json.RawMessage(`{}`),
		due:    time.Now(),
		retry:  RetryLimit,
	})

	require.Equal(t, 1, queueSize(), "a 403 should be requeued")
	assert.True(t, getOne(t).due.After(time.Now()), "the retry should wait")
}

// A retry waiting out its backoff must not hold back an entry that is due, whatever the priorities.
func TestReporter_GivenFutureEntryAheadByPriority_WhenWaitingForEntry_ThenDueEntryComesFirst(t *testing.T) {
	reporter, _ := newTestReporter(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	newRequestQueue()
	Rqueue.Post("/chunk", json.RawMessage(`{}`), 10, time.Now().Add(time.Minute))
	Rqueue.Post("/fin", json.RawMessage(`{}`), 11, time.Time{})

	entry, ok := reporter.waitForEntry(t.Context())

	require.True(t, ok)
	assert.Equal(t, "/fin", entry.url, "the due entry should be taken, not the one still backing off")
}

// A reporter sleeping on a backing-off entry must wake for a new due entry, not finish its sleep.
func TestReporter_GivenOnlyBackingOffEntry_WhenDueEntryEnqueued_ThenTakenWithoutDelay(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		newRequestQueue()
		Rqueue.Post("/chunk", json.RawMessage(`{}`), 10, time.Now().Add(time.Minute))
		reporter := NewReporter(0, nil)
		got := make(chan PriorityEntry, 1)
		go func() {
			entry, _ := reporter.waitForEntry(t.Context())
			got <- entry
		}()
		synctest.Wait()

		start := time.Now()
		Rqueue.Post("/fin", json.RawMessage(`{}`), 11, time.Time{})
		entry := <-got

		assert.Equal(t, "/fin", entry.url)
		assert.Zero(t, time.Since(start), "the reporter should wake on enqueue")
	})
}
