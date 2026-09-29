package runner

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alpacax/alpamon/v2/internal/protocol"
	"github.com/alpacax/alpamon/v2/pkg/agent"
	"github.com/alpacax/alpamon/v2/pkg/config"
	"github.com/alpacax/alpamon/v2/pkg/scheduler"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// startFakeAlpacon stands in for Alpacon, wiring a real scheduler session and
// reporters so PostChunk's delivery can be asserted from real HTTP requests.
func startFakeAlpacon(t *testing.T) (func(), *sync.Mutex, *[]capturedChunk) {
	t.Helper()

	var (
		mu     sync.Mutex
		bodies []capturedChunk
	)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// StartReporters also posts a startup event to the same queue and
		// server; only chunk deliveries matter to these tests.
		if strings.Contains(r.URL.Path, "/chunk/") {
			var chunk protocol.CommandChunk
			_ = json.NewDecoder(r.Body).Decode(&chunk)
			mu.Lock()
			bodies = append(bodies, capturedChunk{path: r.URL.Path, seq: chunk.Seq, content: chunk.Content})
			mu.Unlock()
		}
		w.WriteHeader(http.StatusOK)
	}))

	config.GlobalSettings = config.Settings{
		ServerURL:   server.URL,
		SSLVerify:   false,
		ID:          "test",
		Key:         "test",
		HTTPThreads: 2,
	}

	session := scheduler.InitSession()
	ctxManager := agent.NewContextManager()
	reporterManager := scheduler.StartReporters(session, ctxManager)

	cleanup := func() {
		require.NoError(t, reporterManager.Shutdown(5*time.Second))
		server.Close()
	}

	return cleanup, &mu, &bodies
}

type capturedChunk struct {
	path    string
	seq     int
	content string
}

func TestNewChunkCallback_GivenCtxWithExpiredDeadline_WhenCalled_ThenChunkIsDroppedNotDelivered(t *testing.T) {
	cleanup, mu, bodies := startFakeAlpacon(t)
	defer cleanup()

	cr := NewCommandRunner(nil, nil, protocol.Command{ID: "cmd-1"}, protocol.CommandData{}, nil)
	callback := cr.newChunkCallback()
	require.NotNil(t, callback, "a non-empty command ID should yield a callback")

	// Deadline is far enough in the past that expiry (deadline + the 5m grace) has
	// already elapsed, so processEntry must drop this chunk.
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-6*time.Minute))
	defer cancel()

	callback(ctx, "stale")

	// A second, healthy chunk on its own ctx proves the reporters are alive and
	// processing, so the stale chunk's absence below isn't just a timing fluke.
	liveCallback := cr.newChunkCallback()
	liveCallback(context.Background(), "live")

	require.Eventually(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(*bodies) == 1
	}, 2*time.Second, 10*time.Millisecond, "the live chunk should reach the fake Alpacon server")

	// Give the stale chunk a real, bounded chance to show up too, so the
	// count staying at 1 proves it was dropped rather than merely delayed.
	require.Never(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(*bodies) > 1
	}, 500*time.Millisecond, 20*time.Millisecond, "the expired chunk must never reach the server")

	mu.Lock()
	got := append([]capturedChunk(nil), (*bodies)...)
	mu.Unlock()
	require.Len(t, got, 1, "only the live chunk should have been delivered")
	assert.Equal(t, "live", got[0].content, "the expired chunk must never reach the server")
}

// The final flush of a timed-out command arrives just past its deadline, which is what the grace is for.
func TestNewChunkCallback_GivenCtxDeadlineJustPassed_WhenCalled_ThenChunkIsDeliveredWithinGrace(t *testing.T) {
	cleanup, mu, bodies := startFakeAlpacon(t)
	defer cleanup()

	cr := NewCommandRunner(nil, nil, protocol.Command{ID: "cmd-1"}, protocol.CommandData{}, nil)
	callback := cr.newChunkCallback()
	require.NotNil(t, callback, "a non-empty command ID should yield a callback")

	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()

	callback(ctx, "final flush")

	require.Eventually(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(*bodies) == 1
	}, 2*time.Second, 10*time.Millisecond, "a chunk inside the grace window should reach the fake Alpacon server")
	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, "final flush", (*bodies)[0].content)
}

func TestNewChunkCallback_GivenTwoCallsWithDifferentCtxs_WhenCalled_ThenEachUsesItsOwnCtx(t *testing.T) {
	cleanup, mu, bodies := startFakeAlpacon(t)
	defer cleanup()

	cr := NewCommandRunner(nil, nil, protocol.Command{ID: "cmd-2"}, protocol.CommandData{}, nil)
	callback := cr.newChunkCallback()
	require.NotNil(t, callback)

	// One callback instance, called first with a stale ctx and then a live one:
	// if the callback captured its first ctx instead of using each call's own,
	// the live call would also be dropped and nothing would ever arrive.
	staleCtx, cancel1 := context.WithDeadline(context.Background(), time.Now().Add(-6*time.Minute))
	defer cancel1()
	callback(staleCtx, "stale")

	liveCtx, cancel2 := context.WithTimeout(context.Background(), time.Minute)
	defer cancel2()
	callback(liveCtx, "live")

	require.Eventually(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(*bodies) == 1
	}, 2*time.Second, 10*time.Millisecond, "the live chunk should reach the fake Alpacon server")

	require.Never(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(*bodies) > 1
	}, 500*time.Millisecond, 20*time.Millisecond, "the stale chunk must never reach the server")

	mu.Lock()
	got := append([]capturedChunk(nil), (*bodies)...)
	mu.Unlock()
	require.Len(t, got, 1)
	assert.Equal(t, "live", got[0].content, "the second call's own ctx must have been used, not the first call's")
}

func TestNewChunkCallback_GivenMultipleCalls_WhenCalled_ThenSeqAdvancesMonotonicallyAcrossCalls(t *testing.T) {
	cleanup, mu, bodies := startFakeAlpacon(t)
	defer cleanup()

	cr := NewCommandRunner(nil, nil, protocol.Command{ID: "cmd-3"}, protocol.CommandData{}, nil)
	callback := cr.newChunkCallback()
	require.NotNil(t, callback)

	ctx := context.Background()
	callback(ctx, "a")
	callback(ctx, "b")
	callback(ctx, "c")

	require.Eventually(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(*bodies) == 3
	}, 2*time.Second, 10*time.Millisecond, "all three chunks should reach the fake Alpacon server")

	mu.Lock()
	seqs := []int{(*bodies)[0].seq, (*bodies)[1].seq, (*bodies)[2].seq}
	mu.Unlock()

	// Two reporter goroutines drain concurrently, so delivery order isn't
	// guaranteed; the seq values must still be the distinct, monotonic 0,1,2 handed out.
	assert.ElementsMatch(t, []int{0, 1, 2}, seqs, "seq should advance monotonically, owned by the callback across calls")
}

func TestNewChunkCallback_GivenEmptyCommandID_WhenCalled_ThenCallbackIsNil(t *testing.T) {
	cr := NewCommandRunner(nil, nil, protocol.Command{ID: ""}, protocol.CommandData{}, nil)

	callback := cr.newChunkCallback()

	assert.Nil(t, callback, "an empty command ID must not produce a streaming callback")
}
