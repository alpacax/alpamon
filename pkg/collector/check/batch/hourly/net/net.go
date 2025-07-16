package net

import (
	"context"
	"time"

	"github.com/alpacax/alpamon/pkg/collector/check/base"
	"github.com/alpacax/alpamon/pkg/db/ent"
	"github.com/alpacax/alpamon/pkg/db/ent/traffic"
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

func (c *Check) queryTraffic(ctx context.Context) (base.MetricData, error) {
	queryset, err := c.getTraffic(ctx)
	if err != nil {
		return base.MetricData{}, err
	}

	var data []base.CheckResult
	for _, row := range queryset {
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
		Type: base.HOURLY_NET,
		Data: data,
	}

	err = c.saveHourlyTraffic(data, ctx)
	if err != nil {
		return base.MetricData{}, err
	}

	err = c.deleteTraffic(ctx)
	if err != nil {
		return base.MetricData{}, err
	}

	return metric, nil
}

func (c *Check) getTraffic(ctx context.Context) ([]base.TrafficQuerySet, error) {
	client := c.GetClient()
	now := time.Now()
	from := now.Add(-1 * time.Hour)

	var queryset []base.TrafficQuerySet
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
		).Scan(ctx, &queryset)
	if err != nil {
		return queryset, err
	}

	return queryset, nil
}

func (c *Check) saveHourlyTraffic(data []base.CheckResult, ctx context.Context) error {
	tx, err := c.GetClient().Tx(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	err = tx.HourlyTraffic.MapCreateBulk(data, func(q *ent.HourlyTrafficCreate, i int) {
		q.SetTimestamp(data[i].Timestamp).
			SetName(data[i].Name).
			SetPeakInputPps(data[i].PeakInputPps).
			SetPeakInputBps(data[i].PeakInputBps).
			SetPeakOutputPps(data[i].PeakOutputPps).
			SetPeakOutputBps(data[i].PeakOutputBps).
			SetAvgInputPps(data[i].AvgInputPps).
			SetAvgInputBps(data[i].AvgInputBps).
			SetAvgOutputPps(data[i].AvgOutputPps).
			SetAvgOutputBps(data[i].AvgOutputBps)
	}).Exec(ctx)
	if err != nil {
		return err
	}

	_ = tx.Commit()

	return nil
}

func (c *Check) deleteTraffic(ctx context.Context) error {
	tx, err := c.GetClient().Tx(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	from := time.Now().Add(-1 * time.Hour)

	_, err = tx.Traffic.Delete().
		Where(traffic.TimestampLTE(from)).Exec(ctx)
	if err != nil {
		return err
	}

	_ = tx.Commit()

	return nil
}
