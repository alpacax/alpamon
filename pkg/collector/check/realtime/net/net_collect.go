package net

import (
	"context"
	"time"

	"github.com/alpacax/alpamon/pkg/collector/check/base"
	"github.com/alpacax/alpamon/pkg/db/ent"
	"github.com/alpacax/alpamon/pkg/utils"
	"github.com/shirou/gopsutil/v4/net"
)

type CollectCheck struct {
	base.BaseCheck
	lastMetric map[string]net.IOCountersStat
}

func (c *CollectCheck) Execute(ctx context.Context) error {
	err := c.collectAndSaveTraffic(ctx)
	if err != nil {
		return err
	}

	if ctx.Err() != nil {
		return ctx.Err()
	}

	return nil
}

func (c *CollectCheck) collectAndSaveTraffic(ctx context.Context) error {
	ioCounters, interfaces, err := c.collectTraffic()
	if err != nil {
		return err
	}

	err = c.saveTraffic(c.parseTraffic(ioCounters, interfaces), ctx)
	if err != nil {
		return err
	}

	return nil
}

func (c *CollectCheck) collectTraffic() ([]net.IOCountersStat, map[string]net.InterfaceStat, error) {
	ioCounters, err := c.collectIOCounters()
	if err != nil {
		return nil, nil, err
	}

	interfaces, err := c.collectInterfaces()
	if err != nil {
		return nil, nil, err
	}

	return ioCounters, interfaces, nil
}

func (c *CollectCheck) parseTraffic(ioCOunters []net.IOCountersStat, interfaces map[string]net.InterfaceStat) []base.CheckResult {
	var data []base.CheckResult
	for _, ioCounter := range ioCOunters {
		if _, ok := interfaces[ioCounter.Name]; ok {
			var inputPps, inputBps, outputPps, outputBps float64

			if lastCounter, exists := c.lastMetric[ioCounter.Name]; exists {
				inputPps, outputPps = utils.CalculateNetworkPps(ioCounter, lastCounter, c.GetInterval())
				inputBps, outputBps = utils.CalculateNetworkBps(ioCounter, lastCounter, c.GetInterval())
			} else {
				inputPps = 0
				inputBps = 0
				outputPps = 0
				outputBps = 0
			}

			c.lastMetric[ioCounter.Name] = ioCounter
			data = append(data, base.CheckResult{
				Timestamp: time.Now(),
				Name:      ioCounter.Name,
				InputPps:  &inputPps,
				InputBps:  &inputBps,
				OutputPps: &outputPps,
				OutputBps: &outputBps,
			})
		}
	}
	return data
}

func (c *CollectCheck) collectInterfaces() (map[string]net.InterfaceStat, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	interfaces := utils.FilterVirtualInterface(ifaces)

	return interfaces, nil
}

func (c *CollectCheck) collectIOCounters() ([]net.IOCountersStat, error) {
	ioCounters, err := net.IOCounters(true)
	if err != nil {
		return nil, err
	}

	return ioCounters, nil
}

func (c *CollectCheck) saveTraffic(data []base.CheckResult, ctx context.Context) error {
	client := c.GetClient()
	err := client.Traffic.MapCreateBulk(data, func(q *ent.TrafficCreate, i int) {
		q.SetTimestamp(data[i].Timestamp).
			SetName(data[i].Name).
			SetInputPps(*data[i].InputPps).
			SetInputBps(*data[i].InputBps).
			SetOutputPps(*data[i].OutputPps).
			SetOutputBps(*data[i].OutputBps)
	}).Exec(ctx)
	if err != nil {
		return err
	}

	return nil
}
