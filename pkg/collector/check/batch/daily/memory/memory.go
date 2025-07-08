package memory

import (
	"context"
	"time"

	"github.com/alpacax/alpamon/pkg/collector/check/base"
	"github.com/alpacax/alpamon/pkg/db/ent"
	"github.com/alpacax/alpamon/pkg/db/ent/hourlymemoryusage"
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
	metric, err := c.queryHourlyMemoryUsage(ctx)
	if err != nil {
		return err
	}

	if ctx.Err() != nil {
		return ctx.Err()
	}

	buffer := c.GetBuffer()
	buffer.SuccessQueue <- metric

	return nil
}

func (c *Check) queryHourlyMemoryUsage(ctx context.Context) (base.MetricData, error) {
	querySet, err := c.getHourlyMemoryUsage(ctx)
	if err != nil {
		return base.MetricData{}, err
	}

	data := base.CheckResult{
		Timestamp: time.Now(),
		Peak:      querySet[0].Max,
		Avg:       querySet[0].AVG,
	}
	metric := base.MetricData{
		Type: base.DAILY_MEM_USAGE,
		Data: []base.CheckResult{data},
	}

	err = c.deleteHourlyMemoryUsage(ctx)
	if err != nil {
		return base.MetricData{}, err
	}

	return metric, nil
}

func (c *Check) getHourlyMemoryUsage(ctx context.Context) ([]base.MemoryQuerySet, error) {
	client := c.GetClient()
	now := time.Now()
	from := now.Add(-24 * time.Hour)

	var querySet []base.MemoryQuerySet
	err := client.HourlyMemoryUsage.Query().
		Where(hourlymemoryusage.TimestampGTE(from), hourlymemoryusage.TimestampLTE(now)).
		Aggregate(
			ent.Max(hourlymemoryusage.FieldPeak),
			ent.Mean(hourlymemoryusage.FieldAvg),
		).Scan(ctx, &querySet)
	if err != nil {
		return querySet, err
	}

	return querySet, nil
}

func (c *Check) deleteHourlyMemoryUsage(ctx context.Context) error {
	tx, err := c.GetClient().Tx(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	from := time.Now().Add(-24 * time.Hour)

	_, err = tx.HourlyMemoryUsage.Delete().
		Where(hourlymemoryusage.TimestampLTE(from)).Exec(ctx)
	if err != nil {
		return err
	}

	_ = tx.Commit()

	return nil
}
