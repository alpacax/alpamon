package alert

import (
	"context"
	"time"

	"github.com/alpacax/alpamon/v2/pkg/collector/check/base"
	"github.com/alpacax/alpamon/v2/pkg/scheduler"
)

const (
	alertURL = "/api/metrics/alert-rules/check/"
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
	data := base.AlertData{
		Timestamp:   time.Now().Add(-1 * c.GetInterval()),
		Reporter:    "alpamon",
		Record:      "alert",
		Description: "Alert: detected anomaly",
	}
	scheduler.Rqueue.Post(alertURL, data, 80, time.Time{})

	return nil
}
