package collector

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/alpacax/alpamon/v2/pkg/agent"
	"github.com/alpacax/alpamon/v2/pkg/collector/check"
	"github.com/alpacax/alpamon/v2/pkg/collector/check/base"
	"github.com/alpacax/alpamon/v2/pkg/collector/scheduler"
	"github.com/alpacax/alpamon/v2/pkg/db/ent"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeCheckStrategy is a minimal base.CheckStrategy used to verify which
// entries a fake CheckFactory produced tasks for.
type fakeCheckStrategy struct {
	name string
}

func (f *fakeCheckStrategy) Execute(_ context.Context) error { return nil }
func (f *fakeCheckStrategy) GetInterval() time.Duration      { return time.Second }
func (f *fakeCheckStrategy) GetName() string                 { return f.name }
func (f *fakeCheckStrategy) GetBuffer() *base.CheckBuffer    { return nil }
func (f *fakeCheckStrategy) GetClient() *ent.Client          { return nil }

// stubCheckFactory succeeds only for the check types listed in `known` and
// returns check.CreateCheck's real "unknown check type" style error for
// everything else, mirroring DefaultCheckFactory's behavior without pulling
// in every real check implementation.
type stubCheckFactory struct {
	known map[base.CheckType]bool
}

func (f *stubCheckFactory) CreateCheck(args *base.CheckArgs) (base.CheckStrategy, error) {
	if f.known[args.Type] {
		return &fakeCheckStrategy{name: args.Name}, nil
	}
	return nil, &unknownCheckTypeError{checkType: args.Type}
}

type unknownCheckTypeError struct {
	checkType base.CheckType
}

func (e *unknownCheckTypeError) Error() string {
	return "unknown check type: " + string(e.checkType)
}

func newTestCollector() *Collector {
	return &Collector{
		scheduler: scheduler.NewScheduler(),
		buffer:    base.NewCheckBuffer(10),
		errorChan: make(chan error, 10),
	}
}

func TestInitTasks_SkipsUnknownCheckType(t *testing.T) {
	c := newTestCollector()
	factory := &stubCheckFactory{known: map[base.CheckType]bool{
		base.CPU: true,
		base.Mem: true,
	}}

	args := collectorArgs{
		conf: []collectConf{
			{Type: base.CPU, Interval: 5},
			{Type: base.CheckType("not-a-real-check"), Interval: 5},
			{Type: base.Mem, Interval: 5},
		},
		checkFactory: factory,
	}

	scheduled, err := c.initTasks(args)
	require.NoError(t, err)
	assert.Equal(t, 2, scheduled)
}

func TestInitTasks_AllUnknownReturnsError(t *testing.T) {
	c := newTestCollector()
	factory := &stubCheckFactory{known: map[base.CheckType]bool{}}

	args := collectorArgs{
		conf: []collectConf{
			{Type: base.CheckType("not-a-real-check"), Interval: 5},
			{Type: base.CheckType("also-not-real"), Interval: 5},
		},
		checkFactory: factory,
	}

	scheduled, err := c.initTasks(args)
	require.Error(t, err)
	assert.ErrorContains(t, err, "no usable checks")
	assert.Equal(t, 0, scheduled)
}

func TestInitTasks_EmptyConfigIsNotAnError(t *testing.T) {
	c := newTestCollector()
	factory := &stubCheckFactory{known: map[base.CheckType]bool{}}

	scheduled, err := c.initTasks(collectorArgs{conf: nil, checkFactory: factory})
	require.NoError(t, err)
	assert.Equal(t, 0, scheduled)
}

// Ensure the real factory used in production also exposes the "unknown
// check type" behavior initTasks relies on, in case check.DefaultCheckFactory
// changes shape.
func TestDefaultCheckFactory_ReturnsErrorForUnknownType(t *testing.T) {
	factory := &check.DefaultCheckFactory{}
	_, err := factory.CreateCheck(&base.CheckArgs{Type: base.CheckType("not-a-real-check")})
	assert.Error(t, err)
}

// failingTransporter always fails Send, forcing successQueueWorker onto its
// PublishFailure path.
type failingTransporter struct{}

func (failingTransporter) Send(_ base.MetricData) error {
	return assert.AnError
}

func TestSuccessQueueWorker_ReturnsWhenFailureQueueIsFullAndCtxIsCancelled(t *testing.T) {
	buffer := base.NewCheckBuffer(0)
	c := &Collector{
		transporter: failingTransporter{},
		buffer:      buffer,
	}
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() {
		defer close(done)
		c.successQueueWorker(ctx)
	}()

	sent := make(chan struct{})
	go func() {
		defer close(sent)
		buffer.SuccessQueue <- base.MetricData{Type: base.CPU}
	}()

	select {
	case <-sent:
	case <-time.After(time.Second):
		t.Fatal("worker never received the metric off SuccessQueue")
	}

	// Send failed, so the worker is now parked trying to publish onto a
	// FailureQueue nothing drains; it must not block forever once ctx is
	// cancelled.
	cancel()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("successQueueWorker did not return after ctx was cancelled while the failure queue was full")
	}
}

func assertSuccessQueueOpen(t *testing.T, c *Collector) {
	t.Helper()
	select {
	case _, ok := <-c.buffer.SuccessQueue:
		assert.True(t, ok, "SuccessQueue must never be closed by Stop")
	default:
	}
}

func TestCollector_Stop_NeverClosesSuccessQueueWhenGoroutinesJoin(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c := newTestCollector()
		c.ctxManager = agent.NewContextManager()
		c.errorChan = make(chan error, 10)
		c.ctx, c.cancel = c.ctxManager.NewContext(0)

		done := make(chan struct{})
		c.wg.Go(func() {
			<-c.ctx.Done()
			close(done)
		})

		require.NotPanics(t, func() {
			c.Stop()
		})
		<-done

		assertSuccessQueueOpen(t, c)
	})
}

func TestCollector_Stop_NeverClosesSuccessQueueWhenWaitExpires(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c := newTestCollector()
		c.ctxManager = agent.NewContextManager()
		c.errorChan = make(chan error, 10)
		c.ctx, c.cancel = c.ctxManager.NewContext(0)

		// Ignores ctx and never returns, like a goroutine stuck in a
		// context-unaware syscall.
		hang := make(chan struct{})
		c.wg.Go(func() { <-hang })

		require.NotPanics(t, func() {
			c.Stop()
		})

		assertSuccessQueueOpen(t, c)

		// Unblock the leaked worker so the bubble has nothing left waiting.
		close(hang)
	})
}

func TestCollector_StopIsSafeToCallTwice(t *testing.T) {
	c := newTestCollector()
	c.ctxManager = agent.NewContextManager()
	c.errorChan = make(chan error, 10)
	c.Start()

	require.NotPanics(t, func() {
		c.Stop()
		c.Stop()
	})
}

// recordingTransporter is a transport that always succeeds and counts how
// many metrics it was handed.
type recordingTransporter struct {
	mu   sync.Mutex
	sent int
}

func (f *recordingTransporter) Send(_ base.MetricData) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sent++

	return nil
}

func (f *recordingTransporter) calls() int {
	f.mu.Lock()
	defer f.mu.Unlock()

	return f.sent
}

// hangingTransporter blocks in Send until release is closed, standing in for
// a server that accepts the connection and then says nothing.
type hangingTransporter struct {
	release chan struct{}

	mu       sync.Mutex
	attempts int
}

func (f *hangingTransporter) Send(_ base.MetricData) error {
	f.mu.Lock()
	f.attempts++
	f.mu.Unlock()

	<-f.release

	return errors.New("transport gave up")
}

func (f *hangingTransporter) calls() int {
	f.mu.Lock()
	defer f.mu.Unlock()

	return f.attempts
}

func testMetric() base.MetricData {
	return base.MetricData{
		Type: base.CPU,
		Data: []base.CheckResult{{Timestamp: time.Now(), Usage: 1}},
	}
}

// captureLogs redirects the global logger into a buffer for the duration of
// the test, so a test can assert on what was logged and how often.
func captureLogs(t *testing.T) *bytes.Buffer {
	t.Helper()

	previousLogger, previousLevel := log.Logger, zerolog.GlobalLevel()
	t.Cleanup(func() {
		log.Logger = previousLogger
		zerolog.SetGlobalLevel(previousLevel)
	})

	var buf bytes.Buffer
	log.Logger = zerolog.New(&buf)
	zerolog.SetGlobalLevel(zerolog.InfoLevel)

	return &buf
}

// A restart asked for by the console runs through Stop, and the metrics from
// the last tick are usually still queued when it does. They get one attempt.
func TestStop_FlushesPendingMetrics(t *testing.T) {
	logs := captureLogs(t)

	c := newTestCollector()
	transport := &recordingTransporter{}
	c.transporter = transport

	for range 3 {
		c.buffer.SuccessQueue <- testMetric()
	}
	for range 2 {
		c.buffer.FailureQueue <- testMetric()
	}

	c.Stop()

	assert.Equal(t, 5, transport.calls(), "both queues are flushed, not just the success queue")
	assert.Contains(t, logs.String(), "flushed 5 pending metric(s) on stop, dropped 0")
	c.flushWG.Wait()
}

// Nothing is queued, so there is nothing to say.
func TestStop_LogsNothingWithEmptyQueues(t *testing.T) {
	logs := captureLogs(t)

	c := newTestCollector()
	c.transporter = &recordingTransporter{}

	c.Stop()

	assert.NotContains(t, logs.String(), "pending metric(s) on stop")
}

// The usual reason for a queue to still hold metrics at shutdown is that the
// server stopped answering, so the flush must not hold the restart open for
// as long as the transport is willing to wait.
func TestStop_BoundsTheFlushWhenSendsHang(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		logs := captureLogs(t)

		c := newTestCollector()
		transport := &hangingTransporter{release: make(chan struct{})}
		c.transporter = transport

		for range 4 {
			c.buffer.SuccessQueue <- testMetric()
		}

		start := time.Now()
		c.Stop()
		elapsed := time.Since(start)

		assert.Equal(t, flushTimeout, elapsed, "Stop waits for the bound and not for the transport")
		assert.Contains(t, logs.String(), "flushed 0 pending metric(s) on stop, dropped 4")

		// The send that was still in flight when the bound expired is the
		// only work left, and it ends when the transport returns.
		close(transport.release)
		c.flushWG.Wait()
		assert.Equal(t, 1, transport.calls(), "the flush stops at the send it was in, not at the end of the queue")
	})
}

// The same path with the real workers running.
//
// Stop cancels the collector's context before it drains, and the cancel is
// what ends the workers and leaves metrics behind in the first place. The
// flush still reaches the server from there, because Transporter.Send takes
// no context: the cancel stops the collector, not the transport.
//
// The success queue is drained by the workers, the failure queue is not,
// since failureQueueWorker looks at it once every five seconds. Either way
// every metric is sent exactly once, by a worker or by the flush.
func TestStop_FlushesWhatTheQueueWorkersLeaveBehind(t *testing.T) {
	c := newTestCollector()
	c.ctxManager = agent.NewContextManager()
	transport := &recordingTransporter{}
	c.transporter = transport

	c.Start()

	for range 5 {
		c.buffer.FailureQueue <- testMetric()
	}
	for range 5 {
		c.buffer.SuccessQueue <- testMetric()
	}

	c.Stop()

	require.Error(t, c.ctx.Err(), "the collector's context is already cancelled when the flush runs")
	assert.Equal(t, 10, transport.calls(), "nothing queued at shutdown is dropped while the server is answering")
	c.flushWG.Wait()
}
