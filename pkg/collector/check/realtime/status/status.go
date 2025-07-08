package status

import (
	"context"
	"time"

	"github.com/alpacax/alpamon/pkg/collector/check/base"
	"github.com/alpacax/alpamon/pkg/scheduler"
)

const (
	statusURL = "/api/servers/servers/-/status/"
)

type Check struct {
	base.BaseCheck
}

func NewCheck(args *base.CheckArgs) base.CheckStrategy {
	return &Check{
		BaseCheck: base.NewBaseCheck(args),
	}
}

func (c *Check) Execute(ctx context.Context) error {
	scheduler.Rqueue.Patch(statusURL, nil, 80, time.Time{})

	return nil
}
