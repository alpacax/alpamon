package scheduler

import (
	"context"
	"math"
	"sync"
	"time"

	"github.com/alpacax/alpamon/v2/pkg/agent"
	"github.com/alpacax/alpamon/v2/pkg/collector/check/base"
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
	wg        sync.WaitGroup
	stopOnce  sync.Once
}

type ScheduledTask struct {
	check        base.CheckStrategy
	interval     time.Duration
	mu           sync.Mutex
	nextRun      time.Time
	retryStatus  RetryStatus
	retryPending bool
	running      bool
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
		interval:    interval,
	}
	s.tasks.Store(check.GetName(), task)
}

// Start must run on the caller's goroutine: it registers the goroutines with
// the WaitGroup here, so calling it with go lets Stop reach wg.Wait first.
func (s *Scheduler) Start(ctx context.Context, workerCount int) {
	for range workerCount {
		s.wg.Go(func() { s.worker(ctx) })
	}

	s.wg.Go(func() { s.dispatcher(ctx) })
}

// Stop never closes taskQueue: the dispatcher is its only sender. The join is
// bounded so a context-unaware check cannot hang shutdown forever; on expiry
// it returns false and leaves that goroutine running.
func (s *Scheduler) Stop() bool {
	s.stopOnce.Do(func() { close(s.stopChan) })

	return agent.WaitWithTimeout(&s.wg, agent.ShutdownWaitBudget)
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
			stopped := false
			s.tasks.Range(func(key, value any) bool {
				task, ok := value.(*ScheduledTask)
				if !ok {
					return true
				}

				task.mu.Lock()
				if task.running {
					task.mu.Unlock()
					return true
				}

				due := now.After(task.nextRun)
				if due {
					task.nextRun = now.Add(task.interval)
				}
				retryRequired := task.isRetryRequired(now)

				if !due && !retryRequired {
					task.mu.Unlock()
					return true
				}

				task.running = true
				task.mu.Unlock()

				if !s.send(ctx, task) {
					task.mu.Lock()
					task.running = false
					task.mu.Unlock()
					stopped = true
					return false
				}

				return true
			})
			if stopped {
				return
			}
		}
	}
}

// send pre-checks the stop signals because select picks randomly among ready
// cases, so a free worker would otherwise win the race half the time.
func (s *Scheduler) send(ctx context.Context, task *ScheduledTask) bool {
	select {
	case <-ctx.Done():
		return false
	case <-s.stopChan:
		return false
	default:
	}

	select {
	case s.taskQueue <- task:
		return true
	case <-ctx.Done():
		return false
	case <-s.stopChan:
		return false
	}
}

func (s *Scheduler) worker(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.stopChan:
			return
		case task := <-s.taskQueue:
			select {
			case <-ctx.Done():
				return
			case <-s.stopChan:
				return
			default:
			}
			s.executeTask(ctx, task)
		}
	}
}

func (s *Scheduler) executeTask(ctx context.Context, task *ScheduledTask) {
	defer func() {
		task.mu.Lock()
		task.running = false
		task.mu.Unlock()
	}()

	err := task.check.Execute(ctx)
	if err != nil {
		log.Error().Err(err).Msgf("failed to execute check: %v", err)

		task.mu.Lock()
		if task.retryStatus.attempt < s.retryConf.MaxRetries {
			now := time.Now()
			backoff := time.Duration(math.Pow(2, float64(task.retryStatus.attempt))) * time.Second

			task.retryPending = true
			task.retryStatus.due = now.Add(backoff)
			task.retryStatus.expiry = now.Add(s.retryConf.MaxRetryTime)
			task.retryStatus.attempt++
		} else {
			task.retryPending = false
		}
		task.mu.Unlock()
	} else {
		task.mu.Lock()
		task.retryPending = false
		task.retryStatus.attempt = 0
		task.mu.Unlock()
	}
}

// isRetryRequired reads guarded fields; call only with st.mu held.
func (st *ScheduledTask) isRetryRequired(now time.Time) bool {
	isDue := now.After(st.retryStatus.due)
	isExpire := now.After(st.retryStatus.expiry)

	return st.retryPending && isDue && !isExpire
}
