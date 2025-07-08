package scheduler

import (
	"context"
	"math"
	"sync"
	"time"

	"github.com/alpacax/alpamon/pkg/collector/check/base"
	"github.com/rs/zerolog/log"
)

const (
	MaxRetries    = 5
	MaxRetryTimes = 1 * time.Minute
	DefaultDelay  = 1 * time.Second
)

type Scheduler struct {
	tasks     sync.Map
	retryConf RetryConf
	taskQueue chan *ScheduledTask
	stopChan  chan struct{}
}

type ScheduledTask struct {
	check       base.CheckStrategy
	nextRun     time.Time
	retryStatus RetryStatus
	isSuccess   bool
	interval    time.Duration
}

type RetryConf struct {
	MaxRetries   int
	MaxRetryTime time.Duration
	Delay        time.Duration
}

type RetryStatus struct {
	due     time.Time
	expiry  time.Time
	attempt int
}

func NewScheduler() *Scheduler {
	return &Scheduler{
		retryConf: RetryConf{
			MaxRetries:   MaxRetries,
			MaxRetryTime: MaxRetryTimes,
			Delay:        DefaultDelay,
		},
		taskQueue: make(chan *ScheduledTask),
		stopChan:  make(chan struct{}),
	}
}

func (s *Scheduler) AddTask(check base.CheckStrategy) {
	interval := check.GetInterval()
	retryStatus := RetryStatus{
		due:     time.Now(),
		expiry:  time.Now().Add(s.retryConf.MaxRetryTime),
		attempt: 0,
	}
	task := &ScheduledTask{
		check:       check,
		nextRun:     time.Now().Add(interval),
		retryStatus: retryStatus,
		isSuccess:   true,
		interval:    interval,
	}
	s.tasks.Store(check.GetName(), task)
}

func (s *Scheduler) Start(ctx context.Context, workerCount int) {
	for i := 0; i < workerCount; i++ {
		go s.worker(ctx)
	}

	go s.dispatcher(ctx)
}

func (s *Scheduler) Stop() {
	close(s.stopChan)
	close(s.taskQueue)
}

func (s *Scheduler) dispatcher(ctx context.Context) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-s.stopChan:
			return
		case <-ticker.C:
			now := time.Now()
			s.tasks.Range(func(key, value interface{}) bool {
				task, ok := value.(*ScheduledTask)
				if !ok {
					return true
				}

				if now.After(task.nextRun) {
					task.nextRun = now.Add(task.interval)
					s.taskQueue <- task
				}

				if task.isRetryRequired(now) {
					s.taskQueue <- task
				}

				return true
			})
		}
	}
}

func (s *Scheduler) worker(ctx context.Context) {
	for task := range s.taskQueue {
		select {
		case <-ctx.Done():
			return
		default:
			s.executeTask(ctx, task)
		}
	}
}

func (s *Scheduler) executeTask(ctx context.Context, task *ScheduledTask) {
	err := task.check.Execute(ctx)
	if err != nil {
		log.Error().Err(err).Msgf("failed to execute check: %v", err)

		if task.retryStatus.attempt < s.retryConf.MaxRetries {
			now := time.Now()
			backoff := time.Duration(math.Pow(2, float64(task.retryStatus.attempt))) * time.Second

			task.isSuccess = false
			task.retryStatus.due = now.Add(backoff)
			task.retryStatus.expiry = now.Add(s.retryConf.MaxRetryTime)
			task.retryStatus.attempt++
		}
	} else {
		task.isSuccess = true
		task.retryStatus.attempt = 0
	}
}

func (st *ScheduledTask) isRetryRequired(now time.Time) bool {
	isRetryTask := !st.isSuccess
	isDue := now.After(st.retryStatus.due)
	isExpire := now.After(st.retryStatus.expiry)

	return isRetryTask && isDue && !isExpire
}
