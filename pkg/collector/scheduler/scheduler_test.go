package scheduler

import (
	"context"
	"errors"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/alpacax/alpamon/v2/pkg/collector/check/base"
	"github.com/alpacax/alpamon/v2/pkg/db/ent"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var errTest = errors.New("fakeCheck: forced failure")

// fakeCheck is a base.CheckStrategy whose Execute blocks on a channel the
// test controls, counting how many times it runs.
type fakeCheck struct {
	name     string
	interval time.Duration
	block    chan struct{}
	fail     bool

	mu         sync.Mutex
	calls      int
	callTimes  []time.Time
	current    int
	maxCurrent int
}

func newFakeCheck(name string, interval time.Duration) *fakeCheck {
	return &fakeCheck{name: name, interval: interval, block: make(chan struct{})}
}

func (f *fakeCheck) Execute(ctx context.Context) error {
	f.mu.Lock()
	f.calls++
	f.callTimes = append(f.callTimes, time.Now())
	f.current++
	if f.current > f.maxCurrent {
		f.maxCurrent = f.current
	}
	fail := f.fail
	f.mu.Unlock()

	select {
	case <-f.block:
	case <-ctx.Done():
	}

	f.mu.Lock()
	f.current--
	f.mu.Unlock()

	if fail {
		return errTest
	}
	return nil
}

func (f *fakeCheck) GetInterval() time.Duration   { return f.interval }
func (f *fakeCheck) GetName() string              { return f.name }
func (f *fakeCheck) GetBuffer() *base.CheckBuffer { return nil }
func (f *fakeCheck) GetClient() *ent.Client       { return nil }

func (f *fakeCheck) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func (f *fakeCheck) maxConcurrent() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.maxCurrent
}

// One worker yields one call per tick, so a tick with more than one call
// proves the periodic and the retry dispatch both fired on it.
func (f *fakeCheck) callsAtSameTimestamp() int {
	f.mu.Lock()
	defer f.mu.Unlock()

	counts := make(map[time.Time]int, len(f.callTimes))
	for _, ts := range f.callTimes {
		counts[ts]++
	}
	extra := 0
	for _, n := range counts {
		if n > 1 {
			extra += n - 1
		}
	}
	return extra
}

var _ base.CheckStrategy = (*fakeCheck)(nil)

func TestStop_ReturnsAfterDispatcherWasParkedInASend(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := NewScheduler()
		check := newFakeCheck("blocking", time.Millisecond)
		s.AddTask(check)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		s.Start(ctx, 1)

		// Let the single worker pick up the first run and block inside Execute,
		// then let the dispatcher tick again and park trying to hand over the
		// next run to the now-busy worker.
		time.Sleep(2500 * time.Millisecond)
		synctest.Wait()

		// Call Stop while the dispatcher is still parked in that send and the
		// worker is still busy: this is the state that crashed the process
		// before the fix, on an unrecovered panic in the dispatcher goroutine.
		done := make(chan struct{})
		go func() {
			defer close(done)
			s.Stop()
		}()

		// Give the dispatcher a chance to observe stopChan and return.
		time.Sleep(time.Second)
		synctest.Wait()

		select {
		case <-done:
			t.Fatal("Stop returned before the busy worker finished")
		default:
		}

		// Unblock the busy worker so Stop's wg.Wait can observe it finish.
		close(check.block)
		<-done
	})
}

func TestStop_IsSafeToCallTwice(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := NewScheduler()
		check := newFakeCheck("noop", time.Millisecond)
		close(check.block)
		s.AddTask(check)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		s.Start(ctx, 1)

		// The task is due every millisecond, so by the time we stop, the
		// dispatcher has sent it to the worker one or more times.
		time.Sleep(1100 * time.Millisecond)
		synctest.Wait()

		require.Positive(t, check.callCount())

		require.NotPanics(t, func() {
			s.Stop()
			s.Stop()
		})
	})
}

func TestScheduler_ExecutesATaskWhoseNextRunIsDue(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := NewScheduler()
		check := newFakeCheck("due", time.Millisecond)
		close(check.block)
		s.AddTask(check)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		s.Start(ctx, 1)

		time.Sleep(1100 * time.Millisecond)
		synctest.Wait()

		assert.Equal(t, 1, check.callCount())

		s.Stop()
	})
}

func TestScheduler_FailingCheckRetriesButStopsAtMaxRetriesBound(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := NewScheduler()
		// A long interval keeps the periodic path from firing again, so every
		// call after the first comes from the retry path alone.
		check := newFakeCheck("failing", time.Hour)
		check.fail = true
		close(check.block)
		s.AddTask(check)

		v, _ := s.tasks.Load(check.GetName())
		task := v.(*ScheduledTask)
		task.mu.Lock()
		task.nextRun = time.Now()
		task.mu.Unlock()

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		s.Start(ctx, 1)

		// Observed: 1 initial run + 5 retries (2^0..2^4s backoff) land by 40s,
		// then the count holds at 6 through the retry expiry window.
		time.Sleep(40 * time.Second)
		synctest.Wait()
		require.Equal(t, MaxRetries+1, check.callCount())

		time.Sleep(60 * time.Second)
		synctest.Wait()
		assert.Equal(t, MaxRetries+1, check.callCount(), "no further retries once MaxRetries is exhausted")

		s.Stop()
	})
}

func TestScheduler_SlowCheckNeverRunsConcurrentlyWithItself(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := NewScheduler()
		check := newFakeCheck("slow", time.Millisecond)
		s.AddTask(check)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		// Several workers are free to pick up the task, so only the running
		// guard—not worker scarcity—can prevent a concurrent second run.
		s.Start(ctx, 4)

		// Let many ticks pass while Execute is still blocked on check.block.
		time.Sleep(5 * time.Second)
		synctest.Wait()

		close(check.block)
		time.Sleep(time.Second)
		synctest.Wait()

		assert.Equal(t, 1, check.maxConcurrent())

		s.Stop()
	})
}

// publishingCheck is a base.CheckStrategy whose Execute publishes to a
// buffer's SuccessQueue, letting a test drive a worker that parks there.
type publishingCheck struct {
	name   string
	buffer *base.CheckBuffer
}

func (p *publishingCheck) Execute(ctx context.Context) error {
	return p.buffer.PublishSuccess(ctx, base.MetricData{Type: base.CPU})
}

func (p *publishingCheck) GetInterval() time.Duration   { return time.Millisecond }
func (p *publishingCheck) GetName() string              { return p.name }
func (p *publishingCheck) GetBuffer() *base.CheckBuffer { return p.buffer }
func (p *publishingCheck) GetClient() *ent.Client       { return nil }

var _ base.CheckStrategy = (*publishingCheck)(nil)

func TestStop_ReturnsWhenAWorkerIsParkedPublishingToAFullQueue(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := NewScheduler()
		// Zero-capacity queue that nothing drains, so the first publish fills
		// it and the worker's Execute parks there.
		buffer := base.NewCheckBuffer(0)
		check := &publishingCheck{name: "publishing", buffer: buffer}
		s.AddTask(check)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		s.Start(ctx, 1)

		// Let the worker pick up the due task and park inside PublishSuccess.
		time.Sleep(1100 * time.Millisecond)
		synctest.Wait()

		// Cancel so PublishSuccess observes ctx.Done instead of blocking
		// forever on the full queue; before PublishSuccess became
		// context-aware, this is exactly the state that hung Stop forever.
		cancel()

		done := make(chan struct{})
		go func() {
			defer close(done)
			s.Stop()
		}()

		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("Stop did not return while a worker was parked publishing to a full queue")
		}
	})
}

func TestScheduler_ZeroWorkersDoesNotPanicOnStop(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := NewScheduler()
		// A short interval makes the task due before Stop runs, so with no
		// worker to receive it, the dispatcher really parks in send.
		check := newFakeCheck("noop", time.Millisecond)
		s.AddTask(check)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		s.Start(ctx, 0)

		time.Sleep(1100 * time.Millisecond)
		synctest.Wait()

		require.NotPanics(t, func() {
			s.Stop()
		})
	})
}
