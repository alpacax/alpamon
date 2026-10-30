package runner

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/alpacax/alpamon/v2/internal/pool"

	"github.com/alpacax/alpamon/v2/pkg/agent"
	"github.com/alpacax/alpamon/v2/pkg/config"
	"github.com/alpacax/alpamon/v2/pkg/executor/handlers/common"
	"github.com/alpacax/alpamon/v2/pkg/scheduler"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type cancelTestDispatcher struct {
	cancelBeforeReturn bool
	cancel             func()
	calls              atomic.Int32
	started            chan struct{}
	block              bool
}

func (d *cancelTestDispatcher) HasHandler(string) bool { return true }
func (d *cancelTestDispatcher) Execute(ctx context.Context, _ string, _ *common.CommandArgs) (int, string, error) {
	d.calls.Add(1)
	if d.started != nil {
		close(d.started)
	}
	if d.block {
		<-ctx.Done()
		return 1, "stopped", ctx.Err()
	}
	if d.cancelBeforeReturn {
		d.cancel()
	}
	return 0, "unchanged", nil
}

func cancelTestClient(t *testing.T, d CommandDispatcher) (*WebsocketClient, <-chan map[string]any) {
	t.Helper()
	reports := make(chan map[string]any, 10)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/fin/") {
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			reports <- body
		}
		w.WriteHeader(http.StatusOK)
	}))
	previous := config.GlobalSettings
	config.GlobalSettings = config.Settings{ServerURL: server.URL, HTTPThreads: 1}
	cm := agent.NewContextManager()
	reporters := scheduler.StartReporters(scheduler.InitSession(), cm)
	p := pool.NewPool(1, 10)
	t.Cleanup(func() {
		cm.Shutdown()
		require.NoError(t, p.Shutdown(5*time.Second))
		require.NoError(t, reporters.Shutdown(5*time.Second))
		server.Close()
		config.GlobalSettings = previous
	})
	return &WebsocketClient{pool: p, ctxManager: cm, dispatcher: d}, reports
}
func receiveCancelReport(t *testing.T, reports <-chan map[string]any) map[string]any {
	t.Helper()
	select {
	case report := <-reports:
		return report
	case <-time.After(3 * time.Second):
		t.Fatal("missing finish report")
		return nil
	}
}
func TestCancelBeforeArrival(t *testing.T) {
	d := &cancelTestDispatcher{}
	wc, reports := cancelTestClient(t, d)
	wc.commandRequestHandler([]byte(`{"query":"cancel","command":{"id":"late"}}`))
	wc.commandRequestHandler([]byte(`{"query":"command","command":{"id":"late","shell":"system","line":"ignored"}}`))
	report := receiveCancelReport(t, reports)
	assert.Equal(t, int32(0), d.calls.Load())
	assert.Equal(t, true, report["cancelled"])
	assert.Equal(t, false, report["success"])
	wc.commandRequestHandler([]byte(`{"query":"command","command":{"id":"late","shell":"system","line":"ignored","data":"invalid"}}`))
	report = receiveCancelReport(t, reports)
	assert.Equal(t, true, report["cancelled"], "cancelled redelivery must bypass payload parsing")
	assert.Equal(t, int32(0), d.calls.Load())
}
func TestCancelRunningAndDuplicate(t *testing.T) {
	d := &cancelTestDispatcher{started: make(chan struct{}), block: true}
	wc, reports := cancelTestClient(t, d)
	wc.commandRequestHandler([]byte(`{"query":"command","command":{"id":"running","shell":"system","line":"wait"}}`))
	select {
	case <-d.started:
	case <-time.After(3 * time.Second):
		t.Fatal("command did not start")
	}
	for range 2 {
		wc.commandRequestHandler([]byte(`{"query":"cancel","command":{"id":"running"}}`))
	}
	report := receiveCancelReport(t, reports)
	assert.Equal(t, true, report["cancelled"])
	assert.Equal(t, float64(1), report["exit_code"])
}
func TestCancelUnknownAndOlderServerFlow(t *testing.T) {
	d := &cancelTestDispatcher{}
	wc, reports := cancelTestClient(t, d)
	wc.commandRequestHandler([]byte(`{"query":"cancel","command":{"id":"unknown"}}`))
	wc.commandRequestHandler([]byte(`{"query":"command","command":{"id":"normal","shell":"system","line":"ok"}}`))
	report := receiveCancelReport(t, reports)
	assert.Equal(t, int32(1), d.calls.Load())
	assert.Equal(t, true, report["success"])
	assert.Equal(t, "unchanged", report["result"])
	assert.Equal(t, float64(0), report["exit_code"])
	assert.NotContains(t, report, "cancelled")
	assert.NotContains(t, report, "survivors")
	wc.commandRequestHandler([]byte(`{"query":"cancel","command":{"id":"normal"}}`))
	select {
	case extra := <-reports:
		assert.Failf(t, "unexpected finish report", "%v", extra)
	case <-time.After(50 * time.Millisecond):
	}
}

func TestCancelledIDsBoundedAndExpire(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var registry commandCancellations
		for i := 0; i <= cancelledCommandLimit; i++ {
			registry.cancel(strconv.Itoa(i))
		}
		assert.Len(t, registry.recent, cancelledCommandLimit)
		assert.NotContains(t, registry.recent, "0")
		time.Sleep(cancelledCommandTTL)
		ctx, state := registry.register(context.Background(), "1")
		assert.NoError(t, ctx.Err(), "expired cancellation must not suppress a new delivery")
		registry.finish("1", state)
		assert.Empty(t, registry.recent)
	})
}

func TestCancelQueuedCommandAndReportSurvivors(t *testing.T) {
	d := &cancelTestDispatcher{started: make(chan struct{}), block: true}
	wc, reports := cancelTestClient(t, d)
	wc.commandRequestHandler([]byte(`{"query":"command","command":{"id":"first","shell":"system","line":"wait"}}`))
	select {
	case <-d.started:
	case <-time.After(3 * time.Second):
		t.Fatal("command did not start")
	}
	wc.commandRequestHandler([]byte(`{"query":"command","command":{"id":"queued","shell":"system","line":"never"}}`))
	wc.commandRequestHandler([]byte(`{"query":"cancel","command":{"id":"queued"}}`))
	wc.cancellations.mu.Lock()
	for state := range wc.cancellations.active["first"] {
		state.AddSurvivors([]int{987, 123, 987})
	}
	wc.cancellations.mu.Unlock()
	wc.commandRequestHandler([]byte(`{"query":"cancel","command":{"id":"first"}}`))
	first := receiveCancelReport(t, reports)
	queued := receiveCancelReport(t, reports)
	assert.Equal(t, []any{float64(123), float64(987)}, first["survivors"])
	assert.Equal(t, true, queued["cancelled"])
	assert.Equal(t, int32(1), d.calls.Load())
}

func TestCancellationRegistrationFinishAndDuplicates(t *testing.T) {
	var registry commandCancellations
	ctx, first := registry.register(context.Background(), "same")
	_, second := registry.register(context.Background(), "same")
	registry.finish("same", first)
	registry.cancel("same")
	second.Observe()
	cancelled, _ := registry.finish("same", second)
	assert.True(t, cancelled, "one finished delivery must not hide another running delivery")
	assert.ErrorIs(t, ctx.Err(), context.Canceled)
	late, third := registry.register(context.Background(), "same")
	assert.ErrorIs(t, late.Err(), context.Canceled)
	registry.finish("same", third)

	_, normal := registry.register(context.Background(), "finished")
	registry.finish("finished", normal)
	registry.cancel("finished")
	repeated, fourth := registry.register(context.Background(), "finished")
	assert.NoError(t, repeated.Err(), "cancel after finish must be a no-op")
	registry.finish("finished", fourth)
}

func TestCancelIgnoredByHandlerDoesNotReportCancelled(t *testing.T) {
	d := &cancelTestDispatcher{cancelBeforeReturn: true}
	wc, reports := cancelTestClient(t, d)
	d.cancel = func() { wc.cancellations.cancel("exited") }
	wc.commandRequestHandler([]byte(`{"query":"command","command":{"id":"exited","shell":"system","line":"done"}}`))
	report := receiveCancelReport(t, reports)
	assert.NotContains(t, report, "cancelled")
	assert.Equal(t, true, report["success"])
}

func TestLateCancelDoesNotSuppressRedelivery(t *testing.T) {
	for _, anotherActive := range []bool{false, true} {
		t.Run(strconv.FormatBool(anotherActive), func(t *testing.T) {
			var registry commandCancellations
			_, first := registry.register(context.Background(), "same")
			var finishOther func()
			if anotherActive {
				_, second := registry.register(context.Background(), "same")
				finishOther = func() {
					second.Observe()
					registry.finish("same", second)
				}
			}
			registry.cancel("same")
			cancelled, _ := registry.finish("same", first)
			assert.False(t, cancelled, "the completed delivery did not act on cancellation")
			assert.Equal(t, anotherActive, registry.wasCancelled("same"))
			if finishOther != nil {
				finishOther()
			}
			ctx, repeated := registry.register(context.Background(), "same")
			assert.Equal(t, anotherActive, ctx.Err() != nil, "only effective cancellation may suppress redelivery")
			registry.finish("same", repeated)
		})
	}
}

func TestEffectiveCancelSurvivesDuplicateFinishOrder(t *testing.T) {
	for _, cancelledFirst := range []bool{false, true} {
		t.Run(strconv.FormatBool(cancelledFirst), func(t *testing.T) {
			var registry commandCancellations
			_, effective := registry.register(context.Background(), "same")
			_, normal := registry.register(context.Background(), "same")
			registry.cancel("same")
			effective.Observe()
			if cancelledFirst {
				registry.finish("same", effective)
				registry.cancel("same")
				registry.finish("same", normal)
			} else {
				registry.finish("same", normal)
				registry.finish("same", effective)
			}
			assert.True(t, registry.wasCancelled("same"), "an effective cancellation survives either completion order")
			ctx, repeated := registry.register(context.Background(), "same")
			assert.ErrorIs(t, ctx.Err(), context.Canceled)
			registry.finish("same", repeated)
		})
	}
}

func TestNormalFinishesDoNotEvictPendingCancel(t *testing.T) {
	var registry commandCancellations
	registry.cancel("pending")
	for i := 0; i <= cancelledCommandLimit; i++ {
		id := strconv.Itoa(i)
		_, state := registry.register(context.Background(), id)
		registry.finish(id, state)
	}
	assert.True(t, registry.wasCancelled("pending"))
}

func TestOversizedCancelIDIsIgnored(t *testing.T) {
	var registry commandCancellations
	for _, id := range []string{strings.Repeat("x", 129), strings.Repeat("é", 65)} {
		ctx, state := registry.register(context.Background(), id)
		registry.cancel(id)
		assert.NoError(t, ctx.Err())
		registry.finish(id, state)
		assert.False(t, registry.wasCancelled(id))
	}
	registry.cancel(strings.Repeat("x", 128))
	assert.True(t, registry.wasCancelled(strings.Repeat("x", 128)))
}
