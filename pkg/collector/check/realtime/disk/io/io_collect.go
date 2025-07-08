package diskio

import (
	"context"
	"time"

	"github.com/alpacax/alpamon/pkg/collector/check/base"
	"github.com/alpacax/alpamon/pkg/db/ent"
	"github.com/alpacax/alpamon/pkg/utils"
	"github.com/shirou/gopsutil/v4/disk"
)

type CollectCheck struct {
	base.BaseCheck
	lastMetric map[string]disk.IOCountersStat
}

func (c *CollectCheck) Execute(ctx context.Context) error {
	err := c.collectAndSaveDiskIO(ctx)
	if err != nil {
		return err
	}

	if ctx.Err() != nil {
		return ctx.Err()
	}

	return nil
}

func (c *CollectCheck) collectAndSaveDiskIO(ctx context.Context) error {
	ioCounters, err := c.collectDiskIO()
	if err != nil {
		return err
	}

	err = c.saveDiskIO(c.parseDiskIO(ioCounters), ctx)
	if err != nil {
		return err
	}

	return nil
}

func (c *CollectCheck) parseDiskIO(ioCounters map[string]disk.IOCountersStat) []base.CheckResult {
	var data []base.CheckResult
	seen := make(map[string]bool)
	for name, ioCounter := range ioCounters {
		var readBps, writeBps float64

		if utils.IsVirtualDisk(name) {
			continue
		}

		baseName := utils.GetDiskBaseName(name)
		if seen[baseName] {
			continue
		}
		seen[baseName] = true

		if lastCounter, exist := c.lastMetric[name]; exist {
			readBps, writeBps = utils.CalculateDiskIOBps(ioCounter, lastCounter, c.GetInterval())
		} else {
			readBps = 0
			writeBps = 0
		}

		c.lastMetric[name] = ioCounter
		data = append(data, base.CheckResult{
			Timestamp: time.Now(),
			Device:    baseName,
			ReadBps:   &readBps,
			WriteBps:  &writeBps,
		})
	}

	return data
}

func (c *CollectCheck) collectDiskIO() (map[string]disk.IOCountersStat, error) {
	ioCounters, err := disk.IOCounters()
	if err != nil {
		return nil, err
	}

	return ioCounters, nil
}

func (c *CollectCheck) saveDiskIO(data []base.CheckResult, ctx context.Context) error {
	client := c.GetClient()
	err := client.DiskIO.MapCreateBulk(data, func(q *ent.DiskIOCreate, i int) {
		q.SetTimestamp(data[i].Timestamp).
			SetDevice(data[i].Device).
			SetReadBps(*data[i].ReadBps).
			SetWriteBps(*data[i].WriteBps)
	}).Exec(ctx)
	if err != nil {
		return err
	}

	return nil
}
