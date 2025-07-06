package net

import (
	"context"
	"time"

	"github.com/alpacax/alpamon/pkg/collector/check/base"
	"github.com/alpacax/alpamon/pkg/db/ent"
	"github.com/alpacax/alpamon/pkg/db/ent/traffic"
)

type SendCheck struct {
	base.BaseCheck
}

func (c *SendCheck) Execute(ctx context.Context) error {
	metric, err := c.queryTraffic(ctx)
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

func (c *SendCheck) queryTraffic(ctx context.Context) (base.MetricData, error) {
	querySet, err := c.getTraffic(ctx)
	if err != nil {
		return base.MetricData{}, err
	}

	var data []base.CheckResult
	for _, row := range querySet {
		data = append(data, base.CheckResult{
			Timestamp:     time.Now(),
			Name:          row.Name,
			PeakInputPps:  row.PeakInputPps,
			PeakInputBps:  row.PeakInputBps,
			PeakOutputPps: row.PeakOutputPps,
			PeakOutputBps: row.PeakOutputBps,
			AvgInputPps:   row.AvgInputPps,
			AvgInputBps:   row.AvgInputBps,
			AvgOutputPps:  row.AvgOutputPps,
			AvgOutputBps:  row.AvgOutputBps,
		})
	}
	metric := base.MetricData{
		Type: base.NET,
		Data: data,
	}

	return metric, nil
}

func (c *SendCheck) getTraffic(ctx context.Context) ([]base.TrafficQuerySet, error) {
	client := c.GetClient()
	interval := c.GetInterval()
	now := time.Now()
	from := now.Add(-1 * interval * time.Second)

	var querySet []base.TrafficQuerySet
	err := client.Traffic.Query().
		Where(traffic.TimestampGTE(from), traffic.TimestampLTE(now)).
		GroupBy(traffic.FieldName).
		Aggregate(
			ent.As(ent.Max(traffic.FieldInputPps), "peak_input_pps"),
			ent.As(ent.Max(traffic.FieldInputBps), "peak_input_bps"),
			ent.As(ent.Max(traffic.FieldOutputPps), "peak_output_pps"),
			ent.As(ent.Max(traffic.FieldOutputBps), "peak_output_bps"),
			ent.As(ent.Mean(traffic.FieldInputPps), "avg_input_pps"),
			ent.As(ent.Mean(traffic.FieldInputBps), "avg_input_bps"),
			ent.As(ent.Mean(traffic.FieldOutputPps), "avg_output_pps"),
			ent.As(ent.Mean(traffic.FieldOutputBps), "avg_output_bps"),
		).Scan(ctx, &querySet)
	if err != nil {
		return querySet, err
	}

	return querySet, nil
}
