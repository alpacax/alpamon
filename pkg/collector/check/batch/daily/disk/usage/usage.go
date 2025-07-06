package usage

import (
	"context"
	"time"

	"entgo.io/ent/dialect/sql"
	"github.com/alpacax/alpamon/pkg/collector/check/base"
	"github.com/alpacax/alpamon/pkg/db/ent/hourlydiskusage"
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
	metric, err := c.queryHourlyDiskUsage(ctx)
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

func (c *Check) queryHourlyDiskUsage(ctx context.Context) (base.MetricData, error) {
	querySet, err := c.getHourlyDiskUsage(ctx)
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
		Type: base.DAILY_DISK_USAGE,
		Data: data,
	}

	err = c.deleteHourlyDiskUsage(ctx)
	if err != nil {
		return base.MetricData{}, err
	}

	return metric, nil
}

func (c *Check) getHourlyDiskUsage(ctx context.Context) ([]base.DiskUsageQuerySet, error) {
	client := c.GetClient()

	var querySet []base.DiskUsageQuerySet
	err := client.HourlyDiskUsage.Query().
		Modify(func(s *sql.Selector) {
			now := time.Now()
			from := now.Add(-24 * time.Hour)
			t := sql.Table(hourlydiskusage.Table)

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
				sql.As("peak", "u.peak"),
				sql.As("avg", "u.avg"),
			).
				From(t).
				Where(
					sql.And(
						sql.GTE(t.C(hourlydiskusage.FieldTimestamp), from),
						sql.LTE(t.C(hourlydiskusage.FieldTimestamp), now),
					),
				).
				GroupBy("device", "timestamp").
				As("u")

			*s = *sql.Select(
				sql.As("u.device", "device"),
				sql.As(sql.Max("u.peak"), "max"),
				sql.As(sql.Avg("u.avg"), "avg"),
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

func (c *Check) deleteHourlyDiskUsage(ctx context.Context) error {
	tx, err := c.GetClient().Tx(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	from := time.Now().Add(-24 * time.Hour)

	_, err = tx.HourlyDiskUsage.Delete().
		Where(hourlydiskusage.TimestampLTE(from)).Exec(ctx)
	if err != nil {
		return err
	}

	_ = tx.Commit()

	return nil
}
