// Package pool provides a true worker pool implementation with job queue and context support.
package pool

import (
	"context"
	"fmt"
	"log"
	"runtime/debug"
	"sync"
	"time"
)

// Job represents a unit of work to be executed by the pool
type Job struct {
	fn func() error
}

// Pool represents a pool of workers with a job queue
type Pool struct {
	maxWorkers int
	jobQueue   chan *Job
	ctx        context.Context
	cancel     context.CancelFunc
	wg         sync.WaitGroup
}

// NewPool creates a new worker pool with job queue
func NewPool(maxWorkers int, queueSize int) *Pool {
	if maxWorkers <= 0 {
		maxWorkers = 10
	}
	if queueSize <= 0 {
		queueSize = maxWorkers * 10 // Default queue size
	}

	ctx, cancel := context.WithCancel(context.Background())

	p := &Pool{
		maxWorkers: maxWorkers,
		jobQueue:   make(chan *Job, queueSize),
		ctx:        ctx,
		cancel:     cancel,
	}

	// Start worker goroutines
	p.startWorkers()

	return p
}

// startWorkers launches the worker goroutines
func (p *Pool) startWorkers() {
	for i := 0; i < p.maxWorkers; i++ {
		p.wg.Add(1)
		go p.worker()
	}
}

// worker is the main loop for each worker goroutine
func (p *Pool) worker() {
	defer p.wg.Done()

	for {
		select {
		case job, ok := <-p.jobQueue:
			if !ok {
				// Job queue is closed
				return
			}
			p.executeJob(job)
		case <-p.ctx.Done():
			// Pool is shutting down - drain remaining jobs first
			for {
				select {
				case job, ok := <-p.jobQueue:
					if !ok {
						return
					}
					p.executeJob(job)
				default:
					// No more jobs in queue
					return
				}
			}
		}
	}
}

// executeJob runs a job with panic recovery
func (p *Pool) executeJob(job *Job) {
	// Panic recovery
	defer func() {
		if r := recover(); r != nil {
			log.Printf("recovered from panic in pool worker: %v\nstack: %s", r, debug.Stack())
		}
	}()

	// Execute the function
	err := job.fn()
	if err != nil {
		log.Printf("pool worker error: %v", err)
	}
}

// Submit adds a job to the queue (non-blocking)
// Returns error if the queue is full or pool is shutting down
func (p *Pool) Submit(ctx context.Context, fn func() error) error {
	// Check if pool is shutting down first
	select {
	case <-p.ctx.Done():
		return fmt.Errorf("pool is shutting down")
	default:
	}

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-p.ctx.Done():
		return fmt.Errorf("pool is shutting down")
	case p.jobQueue <- &Job{fn: fn}:
		return nil
	default:
		// Queue is full
		return fmt.Errorf("job queue is full")
	}
}

// QueueSize returns the current number of jobs in the queue
func (p *Pool) QueueSize() int {
	return len(p.jobQueue)
}

// QueueCapacity returns the maximum queue capacity
func (p *Pool) QueueCapacity() int {
	return cap(p.jobQueue)
}

// MaxWorkers returns the number of workers
func (p *Pool) MaxWorkers() int {
	return p.maxWorkers
}

// Shutdown gracefully shuts down the pool
func (p *Pool) Shutdown(timeout time.Duration) error {
	// Signal shutdown to prevent new submissions
	p.cancel()

	// Don't close the job queue immediately - let workers drain it
	// Workers will exit when context is cancelled

	// Wait for all workers to complete
	done := make(chan struct{})
	go func() {
		p.wg.Wait()
		// Close the job queue after all workers have exited
		close(p.jobQueue)
		close(done)
	}()

	select {
	case <-done:
		return nil
	case <-time.After(timeout):
		return fmt.Errorf("shutdown timeout after %v", timeout)
	}
}

// IsShuttingDown returns true if the pool is shutting down
func (p *Pool) IsShuttingDown() bool {
	select {
	case <-p.ctx.Done():
		return true
	default:
		return false
	}
}
