package cpu

import (
	"context"
	"fmt"
	"time"

	"github.com/alpacax/alpamon/pkg/collector/check/base"
	"github.com/shirou/gopsutil/v4/cpu"
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
	metric, err := c.collectAndSaveCPUUsage(ctx)
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

func (c *Check) collectAndSaveCPUUsage(ctx context.Context) (base.MetricData, error) {
	usage, err := c.collectCPUUsage()
	if err != nil {
		return base.MetricData{}, err
	}

	data := base.CheckResult{
		Timestamp: time.Now(),
		Usage:     usage,
	}
	metric := base.MetricData{
		Type: base.CPU,
		Data: []base.CheckResult{data},
	}

	err = c.saveCPUUsage(data, ctx)
	if err != nil {
		return base.MetricData{}, err
	}

	return metric, nil
}

func (c *Check) collectCPUUsage() (float64, error) {
	usage, err := cpu.Percent(0, false)
	if err != nil {
		return 0, err
	}

	if len(usage) == 0 {
		return 0, fmt.Errorf("no cpu usage data returned")
	}

	return usage[0], nil
}

func (c *Check) saveCPUUsage(data base.CheckResult, ctx context.Context) error {
	client := c.GetClient()
	err := client.CPU.Create().
		SetTimestamp(data.Timestamp).
		SetUsage(data.Usage).Exec(ctx)
	if err != nil {
		return err
	}

	return nil
}
