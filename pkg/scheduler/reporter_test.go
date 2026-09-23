package scheduler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
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

	// due is far enough in the past that retry's backoff still leaves the requeued
	// entry immediately due; expiry is a short window that elapses before the retry.
	entry := PriorityEntry{
		method: http.MethodPost,
		url:    "/chunk",
		data:   json.RawMessage(`{}`),
		due:    time.Now().Add(-10 * time.Second),
		expiry: time.Now().Add(50 * time.Millisecond),
		retry:  RetryLimit,
	}

	reporter.query(entry)
	require.Equal(t, int32(1), atomic.LoadInt32(hits), "first attempt should have reached the server")
	require.Equal(t, 1, queueSize(), "failed entry with retries left should be requeued")

	requeued := getOne(t)
	require.False(t, requeued.due.After(time.Now()), "test setup: requeued entry must already be due")

	time.Sleep(60 * time.Millisecond) // let the expiry window elapse, as real backoff wait would
	reporter.processEntry(requeued)

	assert.Equal(t, int32(1), atomic.LoadInt32(hits), "retry/backoff must not resurrect a chunk past its expiry")
}
