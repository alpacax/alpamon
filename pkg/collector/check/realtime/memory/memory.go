package memory

import (
	"context"
	"time"

	"github.com/alpacax/alpamon/pkg/collector/check/base"
	"github.com/shirou/gopsutil/v4/mem"
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
	metric, err := c.collectAndSaveMemoryUsage(ctx)
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

func (c *Check) collectAndSaveMemoryUsage(ctx context.Context) (base.MetricData, error) {
	usage, err := c.collectMemoryUsage()
	if err != nil {
		return base.MetricData{}, err
	}

	data := base.CheckResult{
		Timestamp: time.Now(),
		Usage:     usage,
	}
	metric := base.MetricData{
		Type: base.MEM,
		Data: []base.CheckResult{data},
	}

	err = c.saveMemoryUsage(data, ctx)
	if err != nil {
		return base.MetricData{}, err
	}

	return metric, nil
}

func (c *Check) collectMemoryUsage() (float64, error) {
	memory, err := mem.VirtualMemory()
	if err != nil {
		return 0, err
	}

	return memory.UsedPercent, nil
}

func (c *Check) saveMemoryUsage(data base.CheckResult, ctx context.Context) error {
	client := c.GetClient()
	err := client.Memory.Create().
		SetTimestamp(data.Timestamp).
		SetUsage(data.Usage).Exec(ctx)
	if err != nil {
		return err
	}

	return nil
}
