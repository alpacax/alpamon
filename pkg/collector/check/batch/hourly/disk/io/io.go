package io

import (
	"context"
	"time"

	"github.com/alpacax/alpamon/pkg/collector/check/base"
	"github.com/alpacax/alpamon/pkg/db/ent"
	"github.com/alpacax/alpamon/pkg/db/ent/diskio"
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
	metric, err := c.queryDiskIO(ctx)
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

func (c *Check) queryDiskIO(ctx context.Context) (base.MetricData, error) {
	querySet, err := c.getDiskIO(ctx)
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
		Type: base.HOURLY_DISK_IO,
		Data: data,
	}

	err = c.saveHourlyDiskIO(data, ctx)
	if err != nil {
		return base.MetricData{}, err
	}

	err = c.deleteDiskIO(ctx)
	if err != nil {
		return base.MetricData{}, err
	}

	return metric, nil
}

func (c *Check) getDiskIO(ctx context.Context) ([]base.DiskIOQuerySet, error) {
	client := c.GetClient()
	now := time.Now()
	from := now.Add(-1 * time.Hour)

	var querySet []base.DiskIOQuerySet
	err := client.DiskIO.Query().
		Where(diskio.TimestampGTE(from), diskio.TimestampLTE(now)).
		GroupBy(diskio.FieldDevice).
		Aggregate(
			ent.As(ent.Max(diskio.FieldReadBps), "peak_read_bps"),
			ent.As(ent.Max(diskio.FieldWriteBps), "peak_write_bps"),
			ent.As(ent.Mean(diskio.FieldReadBps), "avg_read_bps"),
			ent.As(ent.Mean(diskio.FieldWriteBps), "avg_write_bps"),
		).Scan(ctx, &querySet)
	if err != nil {
		return querySet, err
	}

	return querySet, nil
}

func (c *Check) saveHourlyDiskIO(data []base.CheckResult, ctx context.Context) error {
	tx, err := c.GetClient().Tx(ctx)
	if err != nil {
		return nil
	}
	defer func() { _ = tx.Rollback() }()

	err = tx.HourlyDiskIO.MapCreateBulk(data, func(q *ent.HourlyDiskIOCreate, i int) {
		q.SetTimestamp(data[i].Timestamp).
			SetDevice(data[i].Device).
			SetPeakReadBps(data[i].PeakReadBps).
			SetPeakWriteBps(data[i].PeakWriteBps).
			SetAvgReadBps(data[i].AvgReadBps).
			SetAvgWriteBps(data[i].AvgWriteBps)
	}).Exec(ctx)
	if err != nil {
		return err
	}

	_ = tx.Commit()

	return nil
}

func (c *Check) deleteDiskIO(ctx context.Context) error {
	tx, err := c.GetClient().Tx(ctx)
	if err != nil {
		return nil
	}
	defer func() { _ = tx.Rollback() }()

	from := time.Now().Add(-1 * time.Hour)

	_, err = tx.DiskIO.Delete().
		Where(diskio.TimestampLTE(from)).Exec(ctx)
	if err != nil {
		return err
	}

	_ = tx.Commit()

	return nil
}
