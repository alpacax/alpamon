package memory

import (
	"context"
	"fmt"
	"time"

	"github.com/alpacax/alpamon/v2/pkg/collector/check/base"
	"github.com/alpacax/alpamon/v2/pkg/db/ent"
	"github.com/alpacax/alpamon/v2/pkg/db/ent/memory"
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
	metric, err := c.queryMemoryUsage(ctx)
	if err != nil {
		return err
	}

	if ctx.Err() != nil {
		return ctx.Err()
	}

	if len(metric.Data) == 0 {
		return nil
	}

	return c.PublishSuccess(ctx, metric)
}

func (c *Check) queryMemoryUsage(ctx context.Context) (base.MetricData, error) {
	querySet, err := c.getMemory(ctx)
	if err != nil {
		return base.MetricData{}, err
	}

	if len(querySet) == 0 {
		err = deleteMemory(ctx, c.GetClient().Memory)
		if err != nil {
			return base.MetricData{}, err
		}
		return base.MetricData{}, nil
	}

	data := base.CheckResult{
		Timestamp: time.Now(),
		Peak:      querySet[0].Max,
		Avg:       querySet[0].AVG,
	}
	metric := base.MetricData{
		Type: base.HourlyMemUsage,
		Data: []base.CheckResult{data},
	}

	err = c.saveHourlyMemoryUsage(data, ctx)
	if err != nil {
		return base.MetricData{}, err
	}

	return metric, nil
}

func (c *Check) getMemory(ctx context.Context) ([]base.MemoryQuerySet, error) {
	client := c.GetClient()
	now := time.Now()
	from := now.Add(-1 * time.Hour)

	var querySet []base.MemoryQuerySet
	err := client.Memory.Query().
		Where(memory.TimestampGTE(from), memory.TimestampLTE(now)).
		Aggregate(
			ent.Max(memory.FieldUsage),
			ent.Mean(memory.FieldUsage),
		).Scan(ctx, &querySet)
	if err != nil {
		return querySet, err
	}

	return querySet, nil
}

func (c *Check) saveHourlyMemoryUsage(data base.CheckResult, ctx context.Context) error {
	tx, err := c.GetClient().Tx(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	err = tx.HourlyMemoryUsage.Create().
		SetTimestamp(data.Timestamp).
		SetPeak(data.Peak).
		SetAvg(data.Avg).Exec(ctx)
	if err != nil {
		return err
	}

	// Prune in the insert's transaction: if the insert committed and the prune failed, the retry would store a second hourly row.
	err = deleteMemory(ctx, tx.Memory)
	if err != nil {
		return err
	}

	if err = tx.Commit(); err != nil {
		return fmt.Errorf("commit hourly memory usage: %w", err)
	}

	return nil
}

func deleteMemory(ctx context.Context, client *ent.MemoryClient) error {
	from := time.Now().Add(-1 * time.Hour)

	_, err := client.Delete().
		Where(memory.TimestampLTE(from)).Exec(ctx)
	return err
}
