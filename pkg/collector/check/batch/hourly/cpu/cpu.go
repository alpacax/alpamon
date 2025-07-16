package cpu

import (
	"context"
	"time"

	"github.com/alpacax/alpamon/pkg/collector/check/base"
	"github.com/alpacax/alpamon/pkg/db/ent"
	"github.com/alpacax/alpamon/pkg/db/ent/cpu"
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
	metric, err := c.queryCPUUsage(ctx)
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

func (c *Check) queryCPUUsage(ctx context.Context) (base.MetricData, error) {
	querySet, err := c.getCPU(ctx)
	if err != nil {
		return base.MetricData{}, err
	}

	data := base.CheckResult{
		Timestamp: time.Now(),
		Peak:      querySet[0].Max,
		Avg:       querySet[0].AVG,
	}
	metric := base.MetricData{
		Type: base.HOURLY_CPU_USAGE,
		Data: []base.CheckResult{data},
	}

	err = c.saveHourlyCPUUsage(data, ctx)
	if err != nil {
		return base.MetricData{}, err
	}

	err = c.deleteCPU(ctx)
	if err != nil {
		return base.MetricData{}, err
	}

	return metric, nil
}

func (c *Check) getCPU(ctx context.Context) ([]base.CPUQuerySet, error) {
	client := c.GetClient()
	now := time.Now()
	from := now.Add(-1 * time.Hour)

	var querySet []base.CPUQuerySet
	err := client.CPU.Query().
		Where(cpu.TimestampGTE(from), cpu.TimestampLTE(now)).
		Aggregate(
			ent.Max(cpu.FieldUsage),
			ent.Mean(cpu.FieldUsage),
		).Scan(ctx, &querySet)
	if err != nil {
		return querySet, err
	}

	return querySet, nil
}

func (c *Check) saveHourlyCPUUsage(data base.CheckResult, ctx context.Context) error {
	tx, err := c.GetClient().Tx(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	err = tx.HourlyCPUUsage.Create().
		SetTimestamp(data.Timestamp).
		SetPeak(data.Peak).
		SetAvg(data.Avg).Exec(ctx)
	if err != nil {
		return err
	}

	_ = tx.Commit()

	return nil
}

func (c *Check) deleteCPU(ctx context.Context) error {
	tx, err := c.GetClient().Tx(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	from := time.Now().Add(-1 * time.Hour)

	_, err = tx.CPU.Delete().
		Where(cpu.TimestampLTE(from)).Exec(ctx)
	if err != nil {
		return err
	}

	_ = tx.Commit()

	return nil
}
