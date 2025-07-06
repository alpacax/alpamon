package cpu

import (
	"context"
	"time"

	"github.com/alpacax/alpamon/pkg/collector/check/base"
	"github.com/alpacax/alpamon/pkg/db/ent"
	"github.com/alpacax/alpamon/pkg/db/ent/hourlycpuusage"
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
	metric, err := c.queryHourlyCPUUsage(ctx)
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

func (c *Check) queryHourlyCPUUsage(ctx context.Context) (base.MetricData, error) {
	querySet, err := c.getHourlyCPUUsage(ctx)
	if err != nil {
		return base.MetricData{}, err
	}

	data := base.CheckResult{
		Timestamp: time.Now(),
		Peak:      querySet[0].Max,
		Avg:       querySet[0].AVG,
	}
	metric := base.MetricData{
		Type: base.DAILY_CPU_USAGE,
		Data: []base.CheckResult{data},
	}

	err = c.deleteHourlyCPUUsage(ctx)
	if err != nil {
		return base.MetricData{}, err
	}

	return metric, nil
}

func (c *Check) getHourlyCPUUsage(ctx context.Context) ([]base.CPUQuerySet, error) {
	client := c.GetClient()
	now := time.Now()
	from := now.Add(-24 * time.Hour)

	var querySet []base.CPUQuerySet
	err := client.HourlyCPUUsage.Query().
		Where(hourlycpuusage.TimestampGTE(from), hourlycpuusage.TimestampLTE(now)).
		Aggregate(
			ent.Max(hourlycpuusage.FieldPeak),
			ent.Mean(hourlycpuusage.FieldAvg),
		).Scan(ctx, &querySet)
	if err != nil {
		return querySet, err
	}

	return querySet, nil
}

func (c *Check) deleteHourlyCPUUsage(ctx context.Context) error {
	tx, err := c.GetClient().Tx(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	from := time.Now().Add(-24 * time.Hour)

	_, err = tx.HourlyCPUUsage.Delete().
		Where(hourlycpuusage.TimestampLTE(from)).Exec(ctx)
	if err != nil {
		return err
	}

	_ = tx.Commit()

	return nil
}
