package collector

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/alpacax/alpamon/pkg/agent"
	"github.com/alpacax/alpamon/pkg/collector/check"
	"github.com/alpacax/alpamon/pkg/collector/check/base"
	"github.com/alpacax/alpamon/pkg/collector/scheduler"
	"github.com/alpacax/alpamon/pkg/collector/transporter"
	"github.com/alpacax/alpamon/pkg/db/ent"
	session "github.com/alpacax/alpamon/pkg/scheduler"
	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
)

const (
	confURL       = "/api/metrics/config/"
	maxRetryCount = 5
	delay         = 1 * time.Second
)

type Collector struct {
	transporter transporter.TransportStrategy
	scheduler   *scheduler.Scheduler
	buffer      *base.CheckBuffer
	errorChan   chan error
	wg          sync.WaitGroup
	ctx         context.Context
	cancel      context.CancelFunc
	ctxManager  *agent.ContextManager
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

	err = metricCollector.initTasks(args)
	if err != nil {
		return nil, err
	}

	return metricCollector, nil
}

func (c *Collector) initTasks(args collectorArgs) error {
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
			return err
		}
		c.scheduler.AddTask(metricCheck)
	}
	return nil
}

func (c *Collector) Start() {
	log.Debug().Msg("Started collector")

	// Use context from global ContextManager instead of creating local context
	c.ctx, c.cancel = c.ctxManager.NewContext(0) // 0 means no timeout

	go c.scheduler.Start(c.ctx, c.buffer.Capacity)

	for i := 0; i < c.buffer.Capacity; i++ {
		c.wg.Add(1)
		go c.successQueueWorker(c.ctx)
	}

	c.wg.Add(1)
	go c.failureQueueWorker(c.ctx)

	go c.handleErrors()
}

func (c *Collector) successQueueWorker(ctx context.Context) {
	defer c.wg.Done()

	for {
		select {
		case <-ctx.Done():
			return
		case metric, ok := <-c.buffer.SuccessQueue:
			if !ok {
				return
			}

			err := c.transporter.Send(metric)
			if err != nil {
				c.buffer.FailureQueue <- metric
			}
		}
	}
}

func (c *Collector) failureQueueWorker(ctx context.Context) {
	defer c.wg.Done()

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
	case metric, ok := <-c.buffer.FailureQueue:
		if !ok {
			return
		}
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
			err := c.transporter.Send(metric)
			if err != nil {
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

func (c *Collector) Stop() {
	if c.cancel != nil {
		c.cancel()
	}

	c.scheduler.Stop()
	c.wg.Wait()

	close(c.buffer.SuccessQueue)
	close(c.buffer.FailureQueue)
	close(c.errorChan)
}
