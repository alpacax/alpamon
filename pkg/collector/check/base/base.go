package base

import (
	"context"
	"time"

	"github.com/alpacax/alpamon/pkg/db/ent"
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

func NewCheckBuffer(capacity int) *CheckBuffer {
	return &CheckBuffer{
		SuccessQueue: make(chan MetricData, capacity),
		FailureQueue: make(chan MetricData, capacity),
		Capacity:     capacity,
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
