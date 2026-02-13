package cpu

import (
	"context"
	"time"

	"github.com/alpacax/alpamon/pkg/collector/check/base"
	"github.com/alpacax/alpamon/pkg/db/ent"
	"github.com/alpacax/alpamon/pkg/db/ent/cpu"
	"github.com/alpacax/alpamon/pkg/db/ent/diskio"
	"github.com/alpacax/alpamon/pkg/db/ent/diskusage"
	"github.com/alpacax/alpamon/pkg/db/ent/hourlycpuusage"
	"github.com/alpacax/alpamon/pkg/db/ent/hourlydiskio"
	"github.com/alpacax/alpamon/pkg/db/ent/hourlydiskusage"
	"github.com/alpacax/alpamon/pkg/db/ent/hourlymemoryusage"
	"github.com/alpacax/alpamon/pkg/db/ent/hourlytraffic"
	"github.com/alpacax/alpamon/pkg/db/ent/memory"
	"github.com/alpacax/alpamon/pkg/db/ent/traffic"
)

var (
	tables = []base.CheckType{
		base.CPU,
		base.HOURLY_CPU_USAGE,
		base.MEM,
		base.HOURLY_MEM_USAGE,
		base.DISK_USAGE,
		base.HOURLY_DISK_USAGE,
		base.DISK_IO,
		base.HOURLY_DISK_IO,
		base.NET,
		base.HOURLY_NET,
	}
	deleteQueryMap = map[base.CheckType]deleteQuery{
		base.CPU:               deleteAllCPU,
		base.HOURLY_CPU_USAGE:  deleteAllHourlyCPUUsage,
		base.MEM:               deleteAllMemory,
		base.HOURLY_MEM_USAGE:  deleteAllHourlyMemoryUsage,
		base.DISK_USAGE:        deleteAllDiskUsage,
		base.HOURLY_DISK_USAGE: deleteAllHourlyDiskUsage,
		base.DISK_IO:           deleteAllDiskIO,
		base.HOURLY_DISK_IO:    deleteAllHourlyDiskIO,
		base.NET:               deleteAllTraffic,
		base.HOURLY_NET:        deleteAllHourlyTraffic,
	}
)

type deleteQuery func(context.Context, *ent.Client, time.Time) error

type Check struct {
	base.BaseCheck
}

func NewCheck(args *base.CheckArgs) base.CheckStrategy {
	return &Check{
		BaseCheck: base.NewBaseCheck(args),
	}
}

func (c *Check) Execute(ctx context.Context) error {
	err := c.deleteAllMetric(ctx)
	if err != nil {
		return err
	}

	if ctx.Err() != nil {
		return ctx.Err()
	}

	return nil
}

func (c *Check) deleteAllMetric(ctx context.Context) error {
	now := time.Now()
	for _, table := range tables {
		if query, exist := deleteQueryMap[table]; exist {
			if err := query(ctx, c.GetClient(), now); err != nil {
				return err
			}
		}
	}

	return nil
}

func deleteAllCPU(ctx context.Context, client *ent.Client, now time.Time) error {
	tx, err := client.Tx(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	_, err = tx.CPU.Delete().
		Where(cpu.TimestampLTE(now.Add(-1 * time.Hour))).Exec(ctx)
	if err != nil {
		return err
	}

	_ = tx.Commit()

	return nil
}

func deleteAllHourlyCPUUsage(ctx context.Context, client *ent.Client, now time.Time) error {
	tx, err := client.Tx(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	_, err = tx.HourlyCPUUsage.Delete().
		Where(hourlycpuusage.TimestampLTE(now.Add(-24 * time.Hour))).Exec(ctx)
	if err != nil {
		return err
	}

	_ = tx.Commit()

	return nil
}

func deleteAllMemory(ctx context.Context, client *ent.Client, now time.Time) error {
	tx, err := client.Tx(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	_, err = tx.Memory.Delete().
		Where(memory.TimestampLTE(now.Add(-1 * time.Hour))).Exec(ctx)
	if err != nil {
		return err
	}

	_ = tx.Commit()

	return nil
}

func deleteAllHourlyMemoryUsage(ctx context.Context, client *ent.Client, now time.Time) error {
	tx, err := client.Tx(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	_, err = tx.HourlyMemoryUsage.Delete().
		Where(hourlymemoryusage.TimestampLTE(now.Add(-24 * time.Hour))).Exec(ctx)
	if err != nil {
		return err
	}

	_ = tx.Commit()

	return nil
}

func deleteAllDiskUsage(ctx context.Context, client *ent.Client, now time.Time) error {
	tx, err := client.Tx(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	_, err = tx.DiskUsage.Delete().
		Where(diskusage.TimestampLTE(now.Add(-1 * time.Hour))).Exec(ctx)
	if err != nil {
		return err
	}

	_ = tx.Commit()

	return nil
}

func deleteAllHourlyDiskUsage(ctx context.Context, client *ent.Client, now time.Time) error {
	tx, err := client.Tx(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	_, err = tx.HourlyDiskUsage.Delete().
		Where(hourlydiskusage.TimestampLTE(now.Add(-24 * time.Hour))).Exec(ctx)
	if err != nil {
		return err
	}

	_ = tx.Commit()

	return nil
}

func deleteAllDiskIO(ctx context.Context, client *ent.Client, now time.Time) error {
	tx, err := client.Tx(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	_, err = client.DiskIO.Delete().
		Where(diskio.TimestampLTE(now.Add(-1 * time.Hour))).Exec(ctx)
	if err != nil {
		return err
	}

	_ = tx.Commit()

	return nil
}

func deleteAllHourlyDiskIO(ctx context.Context, client *ent.Client, now time.Time) error {
	tx, err := client.Tx(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	_, err = tx.HourlyDiskIO.Delete().
		Where(hourlydiskio.TimestampLTE(now.Add(-24 * time.Hour))).Exec(ctx)
	if err != nil {
		return err
	}

	_ = tx.Commit()

	return nil
}

func deleteAllTraffic(ctx context.Context, client *ent.Client, now time.Time) error {
	tx, err := client.Tx(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	_, err = tx.Traffic.Delete().
		Where(traffic.TimestampLTE(now.Add(-1 * time.Hour))).Exec(ctx)
	if err != nil {
		return err
	}

	_ = tx.Commit()

	return nil
}

func deleteAllHourlyTraffic(ctx context.Context, client *ent.Client, now time.Time) error {
	tx, err := client.Tx(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	_, err = tx.HourlyTraffic.Delete().
		Where(hourlytraffic.TimestampLTE(now.Add(-24 * time.Hour))).Exec(ctx)
	if err != nil {
		return err
	}

	_ = tx.Commit()

	return nil
}
