package collector

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/alpacax/alpamon/v2/pkg/agent"
	"github.com/alpacax/alpamon/v2/pkg/collector/check"
	"github.com/alpacax/alpamon/v2/pkg/collector/check/base"
	"github.com/alpacax/alpamon/v2/pkg/collector/scheduler"
	"github.com/alpacax/alpamon/v2/pkg/collector/transporter"
	"github.com/alpacax/alpamon/v2/pkg/db/ent"
	session "github.com/alpacax/alpamon/v2/pkg/scheduler"
	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
)

const (
	confURL       = "/api/metrics/config/"
	maxRetryCount = 5
	delay         = 1 * time.Second

	// flushTimeout bounds how long Stop waits for the metrics still queued
	// when it is called. A planned restart should not throw away the last
	// tick, but a queue that is not empty at shutdown usually means the
	// server is unreachable, so the wait has to end by itself rather than
	// hold the restart open behind a network that is not coming back.
	flushTimeout = 2 * time.Second
)

type Collector struct {
	transporter transporter.TransportStrategy
	scheduler   *scheduler.Scheduler
	buffer      *base.CheckBuffer
	errorChan   chan error
	wg          sync.WaitGroup
	// flushWG covers the goroutine flushPending leaves running when its
	// bound expires while a send is still in flight. Nothing in the agent
	// waits on it, because not waiting is the point of the bound; it is
	// here so that goroutine is accounted for and a test can show it ends
	// when the transport returns rather than leaking.
	flushWG    sync.WaitGroup
	ctx        context.Context
	cancel     context.CancelFunc
	ctxManager *agent.ContextManager
	stopOnce   sync.Once
}

type collectConf struct {
	Type     base.CheckType
	Interval int
}

type collectorArgs struct {
	session          *session.Session
	client           *ent.Client
	conf             []collectConf
	checkFactory     check.CheckFactory
	transportFactory transporter.TransporterFactory
}

func InitCollector(session *session.Session, client *ent.Client, ctxManager *agent.ContextManager) *Collector {
	conf, err := fetchConfig(session)
	if err != nil {
		log.Error().Err(err).Msg("Failed to fetch collector config.")
		return nil
	}

	checkFactory := &check.DefaultCheckFactory{}
	urlResolver := transporter.NewURLResolver()
	transporterFactory := transporter.NewDefaultTransporterFactory(urlResolver)
	args := collectorArgs{
		session:          session,
		client:           client,
		conf:             conf,
		checkFactory:     checkFactory,
		transportFactory: transporterFactory,
	}

	collector, err := NewCollector(args, ctxManager)
	if err != nil {
		log.Error().Err(err).Msg("Failed to create collector.")
		return nil
	}

	return collector
}

func fetchConfig(session *session.Session) ([]collectConf, error) {
	resp, statusCode, err := session.Get(confURL, 10)
	if err != nil {
		return nil, err
	}
	if statusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get collection config: %d status code", statusCode)
	}

	var conf []collectConf
	err = json.Unmarshal(resp, &conf)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	return conf, nil
}

func NewCollector(args collectorArgs, ctxManager *agent.ContextManager) (*Collector, error) {
	metricTransporter, err := args.transportFactory.CreateTransporter(args.session)
	if err != nil {
		return nil, err
	}

	checkBuffer := base.NewCheckBuffer(len(args.conf) * 2)
	metricCollector := &Collector{
		transporter: metricTransporter,
		scheduler:   scheduler.NewScheduler(),
		buffer:      checkBuffer,
		errorChan:   make(chan error, 10),
		ctxManager:  ctxManager,
	}

	scheduled, err := metricCollector.initTasks(args)
	if err != nil {
		return nil, err
	}
	log.Debug().Msgf("Collector scheduled %d check(s).", scheduled)

	return metricCollector, nil
}

// initTasks schedules one task per usable entry in args.conf and returns how
// many were scheduled.
func (c *Collector) initTasks(args collectorArgs) (int, error) {
	scheduled := 0
	skipped := 0
	for _, entry := range args.conf {
		checkArgs := base.CheckArgs{
			Type:     entry.Type,
			Name:     fmt.Sprintf("%s_%s", entry.Type, uuid.NewString()),
			Interval: time.Duration(entry.Interval) * time.Second,
			Buffer:   c.buffer,
			Client:   args.client,
		}

		metricCheck, err := args.checkFactory.CreateCheck(&checkArgs)
		if err != nil {
			// CreateCheck can fail for any reason a factory implementation
			// defines. An unrecognized check type is the common case (e.g.
			// an older binary talking to a newer console), but not the only
			// one. Skip the entry and keep building the rest of the
			// collector instead of failing outright.
			log.Warn().Err(err).Msgf("Failed to create check %q; skipping it.", entry.Type)
			skipped++
			continue
		}
		c.scheduler.AddTask(metricCheck)
		scheduled++
	}

	if len(args.conf) > 0 && skipped == len(args.conf) {
		return scheduled, fmt.Errorf("no usable checks: all %d configured check(s) failed to initialize", len(args.conf))
	}

	return scheduled, nil
}

func (c *Collector) Start() {
	log.Debug().Msg("Started collector")

	// Use context from global ContextManager instead of creating local context
	c.ctx, c.cancel = c.ctxManager.NewContext(0) // 0 means no timeout

	c.scheduler.Start(c.ctx, c.buffer.Capacity)

	ctx := c.ctx // read here, so no worker goroutine touches c.ctx itself
	for range c.buffer.Capacity {
		c.wg.Go(func() { c.successQueueWorker(ctx) })
	}

	c.wg.Go(func() { c.failureQueueWorker(ctx) })

	go c.handleErrors()
}

func (c *Collector) successQueueWorker(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case metric := <-c.buffer.SuccessQueue:
			// ErrRejected means the server has already refused this metric
			// and would refuse it again, so it is handled like success here:
			// left off the retry queue. flushPending is what still needs to
			// tell the two apart, off Send's return value directly.
			err := c.transporter.Send(metric)
			if err != nil && !errors.Is(err, transporter.ErrRejected) {
				if pubErr := c.buffer.PublishFailure(ctx, metric); pubErr != nil {
					return
				}
			}
		}
	}
}

func (c *Collector) failureQueueWorker(ctx context.Context) {
	retryTicker := time.NewTicker(5 * time.Second)
	defer retryTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-retryTicker.C:
			c.retryFailedMetrics(ctx)
		}
	}
}

func (c *Collector) retryFailedMetrics(ctx context.Context) {
	select {
	case metric := <-c.buffer.FailureQueue:
		err := c.retryWithBackoff(ctx, metric)
		if err != nil {
			log.Error().Err(err).Msgf("Failed to check metric: %s.", metric.Type)
		}
	default:
		return
	}
}

func (c *Collector) retryWithBackoff(ctx context.Context, metric base.MetricData) error {
	retryCount := 0
	for retryCount < maxRetryCount {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Duration(1<<retryCount) * delay):
			// ErrRejected stops the retry loop the same way success does:
			// the server has already refused this metric and would refuse
			// it again.
			err := c.transporter.Send(metric)
			if err != nil && !errors.Is(err, transporter.ErrRejected) {
				retryCount++
				continue
			}

			return nil
		}
	}

	return fmt.Errorf("max retries exceeded for metric %s", metric.Type)
}

func (c *Collector) handleErrors() {
	for err := range c.errorChan {
		log.Error().Err(err).Msgf("Collector error: %v.", err)
	}
}

// Stop never closes the metric queues—a check still running past the
// bounded wait could still publish, racing a send against a closed channel.
func (c *Collector) Stop() {
	c.stopOnce.Do(func() {
		if c.cancel != nil {
			c.cancel()
		}

		if !c.scheduler.Stop() {
			log.Warn().Msgf("scheduler did not join within %s", agent.ShutdownWaitBudget)
		}
		if !agent.WaitWithTimeout(&c.wg, agent.ShutdownWaitBudget) {
			log.Warn().Msgf("collector goroutines did not join within %s", agent.ShutdownWaitBudget)
		}

		// A fresh context: the collector's own is already cancelled above, and
		// the flush is the one piece of work that has to outlive the cancel.
		ctx, cancel := context.WithTimeout(context.Background(), flushTimeout)
		defer cancel()

		sent, dropped := c.flushPending(ctx)
		if sent+dropped > 0 {
			log.Info().Msgf("Collector flushed %d pending metric(s) on stop, dropped %d.", sent, dropped)
		}

		// errorChan has no sender anywhere, so no straggler can race this
		// close, and handleErrors leaks on every restart without it.
		close(c.errorChan)
	})
}

// flushPending empties both queues and attempts each metric once, with no
// backoff and no second attempt, and reports how many reached the server and
// how many did not.
//
// This is the last thing that happens to a metric that was still queued when
// the collector stopped. Nothing is written back to a queue and nothing is
// persisted, so a metric that does not go out here is gone; the hourly and
// daily rollups computed from the local database are what remains of it.
// Failures are not logged one by one: a queue that is not empty at shutdown
// is usually a queue whose sends were already failing, and one line per
// metric would repeat a single fact.
//
// ctx bounds the wait, not the sends. Transporter.Send carries no context
// and sets its own request timeout, so the bound is read between metrics:
// flushPending returns the moment ctx expires, and the send that was in
// flight keeps running until the transport gives up on it. Stop therefore
// returns within flushTimeout, while the goroutine behind it can outlive
// Stop by one transport timeout and no more, since the next iteration sees
// ctx and stops. The metric that send was carrying is counted as dropped
// whatever it goes on to do.
//
// Stop is what establishes the preconditions, and neither one is a hard
// guarantee: both are bounded by ShutdownWaitBudget, not joined
// unconditionally. Readers: Stop's own wait on wg can expire with a worker
// still running, and that worker can still be receiving from the same
// queue the drain is reading. Writers: Scheduler.Stop joins the scheduler's
// goroutines within the same budget, so a check that has not returned
// within it can still publish after the drain has gone past. Either way a
// straggler races the drain for individual metrics, not the channel, so
// nothing panics and nothing is double-counted—a metric they were both
// about to take simply goes to whichever gets there first, and a check that
// publishes after the drain has gone past is dropped exactly as it is
// dropped today. Ordinarily both waits join well within their budget, so
// the drain has the queues to itself.
func (c *Collector) flushPending(ctx context.Context) (sent int, dropped int) {
	pending := append(drainQueue(c.buffer.SuccessQueue), drainQueue(c.buffer.FailureQueue)...)
	if len(pending) == 0 {
		return 0, 0
	}

	var flushed atomic.Int64
	done := make(chan struct{})

	c.flushWG.Add(1)
	go func() {
		defer c.flushWG.Done()
		defer close(done)

		for _, metric := range pending {
			select {
			case <-ctx.Done():
				return
			default:
			}

			// err == nil is a true delivery here, not just "do not retry":
			// transporter.ErrRejected is a distinct non-nil error, so a
			// metric the server rejected with 400 counts as dropped below,
			// the same as one a timeout or a dead connection took down.
			if err := c.transporter.Send(metric); err == nil {
				flushed.Add(1)
			}
		}
	}()

	select {
	case <-done:
	case <-ctx.Done():
	}

	sent = int(flushed.Load())

	return sent, len(pending) - sent
}

// drainQueue takes everything queue holds right now, without blocking and
// without waiting for more.
func drainQueue(queue <-chan base.MetricData) []base.MetricData {
	var drained []base.MetricData
	for {
		select {
		case metric, ok := <-queue:
			if !ok {
				return drained
			}
			drained = append(drained, metric)
		default:
			return drained
		}
	}
}
