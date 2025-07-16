package usage

import (
	"context"
	"time"

	"entgo.io/ent/dialect/sql"
	"github.com/alpacax/alpamon/pkg/collector/check/base"
	"github.com/alpacax/alpamon/pkg/db/ent"
	"github.com/alpacax/alpamon/pkg/db/ent/diskusage"
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
	metric, err := c.queryDiskUsage(ctx)
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

func (c *Check) queryDiskUsage(ctx context.Context) (base.MetricData, error) {
	querySet, err := c.getDiskUsage(ctx)
	if err != nil {
		return base.MetricData{}, err
	}

	var data []base.CheckResult
	for _, row := range querySet {
		data = append(data, base.CheckResult{
			Timestamp: time.Now(),
			Device:    row.Device,
			Peak:      row.Max,
			Avg:       row.AVG,
			Total:     row.Total,
			Free:      row.Free,
			Used:      row.Used,
		})
	}
	metric := base.MetricData{
		Type: base.HOURLY_DISK_USAGE,
		Data: data,
	}

	err = c.saveHourlyDiskUsage(data, ctx)
	if err != nil {
		return base.MetricData{}, err
	}

	err = c.deleteDiskUsage(ctx)
	if err != nil {
		return base.MetricData{}, err
	}

	return metric, nil
}

func (c *Check) getDiskUsage(ctx context.Context) ([]base.DiskUsageQuerySet, error) {
	client := c.GetClient()

	var querySet []base.DiskUsageQuerySet
	err := client.DiskUsage.Query().
		Modify(func(s *sql.Selector) {
			now := time.Now()
			from := now.Add(-1 * time.Hour)
			usageExpr := "(CAST(SUM(used) AS FLOAT) * 100.0) / NULLIF(SUM(total), 0)"
			t := sql.Table(diskusage.Table)

			latestSubq := sql.Select(
				sql.As("device", "l.device"),
				sql.As("used", "l.used"),
				sql.As("total", "l.total"),
				sql.As("free", "l.free"),
			).
				From(t).
				Where(
					sql.In("timestamp",
						sql.Select(sql.Max("timestamp")).From(t).GroupBy("device"),
					),
				).
				As("l")

			usageSubq := sql.Select(
				sql.As("device", "u.device"),
				"timestamp",
				sql.As(usageExpr, "usage"),
			).
				From(t).
				Where(
					sql.And(
						sql.GTE(t.C(diskusage.FieldTimestamp), from),
						sql.LTE(t.C(diskusage.FieldTimestamp), now),
					),
				).
				GroupBy("device", "timestamp").
				As("u")

			*s = *sql.Select(
				sql.As("u.device", "device"),
				sql.As(sql.Max("usage"), "max"),
				sql.As(sql.Avg("usage"), "avg"),
				sql.As("l.used", "used"),
				sql.As("l.total", "total"),
				sql.As("l.free", "free"),
			).
				From(usageSubq).
				Join(latestSubq).
				On("u.device", "l.device").
				GroupBy("u.device")
		}).Scan(ctx, &querySet)
	if err != nil {
		return querySet, err
	}

	return querySet, nil
}

func (c *Check) saveHourlyDiskUsage(data []base.CheckResult, ctx context.Context) error {
	tx, err := c.GetClient().Tx(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	err = tx.HourlyDiskUsage.MapCreateBulk(data, func(q *ent.HourlyDiskUsageCreate, i int) {
		q.SetTimestamp(data[i].Timestamp).
			SetDevice(data[i].Device).
			SetPeak(data[i].Peak).
			SetAvg(data[i].Avg).
			SetTotal(int64(data[i].Total)).
			SetFree(int64(data[i].Free)).
			SetUsed(int64(data[i].Used))
	}).Exec(ctx)
	if err != nil {
		return err
	}

	_ = tx.Commit()

	return nil
}

func (c *Check) deleteDiskUsage(ctx context.Context) error {
	tx, err := c.GetClient().Tx(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	from := time.Now().Add(-1 * time.Hour)

	_, err = tx.DiskUsage.Delete().
		Where(diskusage.TimestampLTE(from)).Exec(ctx)
	if err != nil {
		return err
	}

	_ = tx.Commit()

	return nil
}
