package net

import (
	"context"
	"time"

	"github.com/alpacax/alpamon/pkg/collector/check/base"
	"github.com/alpacax/alpamon/pkg/db/ent"
	"github.com/alpacax/alpamon/pkg/db/ent/hourlytraffic"
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
	metric, err := c.queryHourlyTraffic(ctx)
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

func (c *Check) queryHourlyTraffic(ctx context.Context) (base.MetricData, error) {
	querySet, err := c.getHourlyTraffic(ctx)
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
		Type: base.DAILY_NET,
		Data: data,
	}

	err = c.deleteHourlyTraffic(ctx)
	if err != nil {
		return base.MetricData{}, err
	}

	return metric, nil
}

func (c *Check) getHourlyTraffic(ctx context.Context) ([]base.TrafficQuerySet, error) {
	client := c.GetClient()
	now := time.Now()
	from := now.Add(-24 * time.Hour)

	var querySet []base.TrafficQuerySet
	err := client.HourlyTraffic.Query().
		Where(hourlytraffic.TimestampGTE(from), hourlytraffic.TimestampLTE(now)).
		GroupBy(hourlytraffic.FieldName).
		Aggregate(
			ent.As(ent.Max(hourlytraffic.FieldPeakInputPps), "peak_input_pps"),
			ent.As(ent.Max(hourlytraffic.FieldPeakInputBps), "peak_input_bps"),
			ent.As(ent.Max(hourlytraffic.FieldPeakOutputPps), "peak_output_pps"),
			ent.As(ent.Max(hourlytraffic.FieldPeakOutputBps), "peak_output_bps"),
			ent.As(ent.Mean(hourlytraffic.FieldAvgInputPps), "avg_input_pps"),
			ent.As(ent.Mean(hourlytraffic.FieldAvgInputBps), "avg_input_bps"),
			ent.As(ent.Mean(hourlytraffic.FieldAvgOutputPps), "avg_output_pps"),
			ent.As(ent.Mean(hourlytraffic.FieldAvgOutputBps), "avg_output_bps"),
		).Scan(ctx, &querySet)
	if err != nil {
		return querySet, err
	}

	return querySet, nil
}

func (c *Check) deleteHourlyTraffic(ctx context.Context) error {
	tx, err := c.GetClient().Tx(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	from := time.Now().Add(-24 * time.Hour)

	_, err = tx.HourlyTraffic.Delete().
		Where(hourlytraffic.TimestampLTE(from)).Exec(ctx)
	if err != nil {
		return err
	}

	_ = tx.Commit()

	return nil
}
