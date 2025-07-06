package io

import (
	"context"
	"time"

	"github.com/alpacax/alpamon/pkg/collector/check/base"
	"github.com/alpacax/alpamon/pkg/db/ent"
	"github.com/alpacax/alpamon/pkg/db/ent/hourlydiskio"
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
	metric, err := c.queryHourlyDiskIO(ctx)
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

func (c *Check) queryHourlyDiskIO(ctx context.Context) (base.MetricData, error) {
	querySet, err := c.getHourlyDiskIO(ctx)
	if err != nil {
		return base.MetricData{}, err
	}

	var data []base.CheckResult
	for _, row := range querySet {
		data = append(data, base.CheckResult{
			Timestamp:    time.Now(),
			Device:       row.Device,
			PeakWriteBps: row.PeakWriteBps,
			PeakReadBps:  row.PeakReadBps,
			AvgWriteBps:  row.AvgWriteBps,
			AvgReadBps:   row.AvgReadBps,
		})
	}
	metric := base.MetricData{
		Type: base.DAILY_DISK_IO,
		Data: data,
	}

	err = c.deleteHourlyDiskIO(ctx)
	if err != nil {
		return base.MetricData{}, err
	}

	return metric, nil
}

func (c *Check) getHourlyDiskIO(ctx context.Context) ([]base.DiskIOQuerySet, error) {
	client := c.GetClient()
	now := time.Now()
	from := now.Add(-24 * time.Hour)

	var querySet []base.DiskIOQuerySet
	err := client.HourlyDiskIO.Query().
		Where(hourlydiskio.TimestampGTE(from), hourlydiskio.TimestampLTE(now)).
		GroupBy(hourlydiskio.FieldDevice).
		Aggregate(
			ent.As(ent.Max(hourlydiskio.FieldPeakReadBps), "peak_read_bps"),
			ent.As(ent.Max(hourlydiskio.FieldPeakWriteBps), "peak_write_bps"),
			ent.As(ent.Mean(hourlydiskio.FieldAvgReadBps), "avg_read_bps"),
			ent.As(ent.Mean(hourlydiskio.FieldAvgWriteBps), "avg_write_bps"),
		).Scan(ctx, &querySet)
	if err != nil {
		return querySet, err
	}

	return querySet, nil
}

func (c *Check) deleteHourlyDiskIO(ctx context.Context) error {
	tx, err := c.GetClient().Tx(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	from := time.Now().Add(-24 * time.Hour)

	_, err = tx.HourlyDiskIO.Delete().
		Where(hourlydiskio.TimestampLTE(from)).Exec(ctx)
	if err != nil {
		return err
	}

	_ = tx.Commit()

	return nil
}
