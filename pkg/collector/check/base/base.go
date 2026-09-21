package base

import (
	"context"
	"time"

	"github.com/alpacax/alpamon/v2/pkg/db/ent"
)

type CheckStrategy interface {
	Execute(ctx context.Context) error
	GetInterval() time.Duration
	GetName() string
	GetBuffer() *CheckBuffer
	GetClient() *ent.Client
}

type BaseCheck struct {
	name     string
	interval time.Duration
	buffer   *CheckBuffer
	client   *ent.Client
}

func NewBaseCheck(args *CheckArgs) BaseCheck {
	return BaseCheck{
		name:     args.Name,
		interval: args.Interval,
		buffer:   args.Buffer,
		client:   args.Client,
	}
}

func (c *BaseCheck) GetName() string {
	return c.name
}

func (c *BaseCheck) GetInterval() time.Duration {
	return c.interval
}

func (c *BaseCheck) GetBuffer() *CheckBuffer {
	return c.buffer
}

func (c *BaseCheck) GetClient() *ent.Client {
	return c.client
}

func (c *BaseCheck) PublishSuccess(ctx context.Context, metric MetricData) error {
	return c.buffer.PublishSuccess(ctx, metric)
}

func NewCheckBuffer(capacity int) *CheckBuffer {
	return &CheckBuffer{
		SuccessQueue: make(chan MetricData, capacity),
		FailureQueue: make(chan MetricData, capacity),
		Capacity:     capacity,
	}
}

func (b *CheckBuffer) PublishSuccess(ctx context.Context, metric MetricData) error {
	return publish(ctx, b.SuccessQueue, metric)
}

func (b *CheckBuffer) PublishFailure(ctx context.Context, metric MetricData) error {
	return publish(ctx, b.FailureQueue, metric)
}

// publish takes ctx because these queues can stop being drained during
// shutdown, where a plain send would block forever.
func publish(ctx context.Context, queue chan<- MetricData, metric MetricData) error {
	select {
	case queue <- metric:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
