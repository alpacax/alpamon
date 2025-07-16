package diskusage

import (
	"context"
	"strings"
	"time"

	"github.com/alpacax/alpamon/pkg/collector/check/base"
	"github.com/alpacax/alpamon/pkg/db/ent"
	"github.com/alpacax/alpamon/pkg/utils"
	"github.com/shirou/gopsutil/v4/disk"
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
	metric, err := c.collectAndSaveDiskUsage(ctx)
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

func (c *Check) collectAndSaveDiskUsage(ctx context.Context) (base.MetricData, error) {
	partitions, err := c.collectDiskPartitions()
	if err != nil {
		return base.MetricData{}, err
	}

	metric := base.MetricData{
		Type: base.DISK_USAGE,
		Data: c.parseDiskUsage(partitions),
	}

	err = c.saveDiskUsage(metric.Data, ctx)
	if err != nil {
		return base.MetricData{}, err
	}

	return metric, nil
}

func (c *Check) parseDiskUsage(partitions []disk.PartitionStat) []base.CheckResult {
	var data []base.CheckResult
	seen := make(map[string]bool)
	for _, partition := range partitions {
		if seen[partition.Device] {
			continue
		}
		seen[partition.Device] = true

		usage, err := c.collectDiskUsage(partition.Mountpoint)
		if err == nil {
			data = append(data, base.CheckResult{
				Timestamp: time.Now(),
				Device:    partition.Device,
				Usage:     usage.UsedPercent,
				Total:     usage.Total,
				Free:      usage.Free,
				Used:      usage.Used,
			})
		}
	}

	return data
}

func (c *Check) collectDiskPartitions() ([]disk.PartitionStat, error) {
	partitions, err := disk.Partitions(true)
	if err != nil {
		return nil, err
	}

	var filteredPartitions []disk.PartitionStat
	for _, partition := range partitions {
		if utils.IsVirtualFileSystem(partition.Device, partition.Fstype, partition.Mountpoint) {
			continue
		}

		if strings.HasPrefix(partition.Device, "/dev") {
			filteredPartitions = append(filteredPartitions, partition)
		}
	}

	return filteredPartitions, nil
}

func (c *Check) collectDiskUsage(path string) (*disk.UsageStat, error) {
	usage, err := disk.Usage(path)
	if err != nil {
		return nil, err
	}

	return usage, nil
}

func (c *Check) saveDiskUsage(data []base.CheckResult, ctx context.Context) error {
	client := c.GetClient()
	err := client.DiskUsage.MapCreateBulk(data, func(q *ent.DiskUsageCreate, i int) {
		q.SetTimestamp(data[i].Timestamp).
			SetDevice(data[i].Device).
			SetUsage(data[i].Usage).
			SetTotal(int64(data[i].Total)).
			SetFree(int64(data[i].Free)).
			SetUsed(int64(data[i].Used))
	}).Exec(ctx)
	if err != nil {
		return err
	}

	return nil
}
