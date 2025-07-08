package diskio

import (
	"context"
	"time"

	"github.com/alpacax/alpamon/pkg/collector/check/base"
	"github.com/alpacax/alpamon/pkg/db/ent"
	"github.com/alpacax/alpamon/pkg/db/ent/diskio"
)

type SendCheck struct {
	base.BaseCheck
}

func (c *SendCheck) Execute(ctx context.Context) error {
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

func (c *SendCheck) queryDiskIO(ctx context.Context) (base.MetricData, error) {
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
		Type: base.DISK_IO,
		Data: data,
	}

	return metric, nil
}

func (c *SendCheck) getDiskIO(ctx context.Context) ([]base.DiskIOQuerySet, error) {
	client := c.GetClient()
	interval := c.GetInterval()
	now := time.Now()
	from := now.Add(-1 * interval * time.Second)

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
