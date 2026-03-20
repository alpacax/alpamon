package base

import (
	"time"

	"github.com/alpacax/alpamon/pkg/db/ent"
)

const (
	CPU              CheckType = "cpu"
	HourlyCPUUsage   CheckType = "hourly-cpu-usage"
	DailyCPUUsage    CheckType = "daily-cpu-usage"
	Mem              CheckType = "memory"
	HourlyMemUsage   CheckType = "hourly-memory-usage"
	DailyMemUsage    CheckType = "daily-memory-usage"
	DiskUsage        CheckType = "disk-usage"
	HourlyDiskUsage  CheckType = "hourly-disk-usage"
	DailyDiskUsage   CheckType = "daily-disk-usage"
	DiskIO           CheckType = "disk-io"
	DiskIOCollector  CheckType = "disk-io-collector"
	HourlyDiskIO     CheckType = "hourly-disk-io"
	DailyDiskIO      CheckType = "daily-disk-io"
	Net              CheckType = "net"
	NetCollector     CheckType = "net-collector"
	HourlyNet        CheckType = "hourly-net"
	DailyNet         CheckType = "daily-net"
	Cleanup          CheckType = "cleanup"
	Alert            CheckType = "alert"
	Status           CheckType = "status"
)

type CheckType string

type CheckArgs struct {
	Type     CheckType
	Name     string
	Interval time.Duration
	Buffer   *CheckBuffer
	Client   *ent.Client
}

type AlertData struct {
	Timestamp   time.Time `json:"timestamp"`
	Reporter    string    `json:"reporter"`
	Record      string    `json:"record"`
	Description string    `json:"description"`
}

type CPUQuerySet struct {
	Max float64
	AVG float64
}

type MemoryQuerySet struct {
	Max float64
	AVG float64
}

type DiskIOQuerySet struct {
	Device       string  `json:"device" db:"device"`
	PeakReadBps  float64 `json:"peak_read_bps"`
	PeakWriteBps float64 `json:"peak_write_bps"`
	AvgReadBps   float64 `json:"avg_read_bps"`
	AvgWriteBps  float64 `json:"avg_write_bps"`
}

type DiskUsageQuerySet struct {
	Device string  `json:"device"`
	Max    float64 `json:"max"`
	AVG    float64 `json:"avg"`
	Total  uint64  `json:"total"`
	Free   uint64  `json:"free"`
	Used   uint64  `json:"used"`
}

type TrafficQuerySet struct {
	Name          string  `json:"name"`
	PeakInputPps  float64 `json:"peak_input_pps"`
	PeakInputBps  float64 `json:"peak_input_bps"`
	PeakOutputPps float64 `json:"peak_output_pps"`
	PeakOutputBps float64 `json:"peak_output_bps"`
	AvgInputPps   float64 `json:"avg_input_pps"`
	AvgInputBps   float64 `json:"avg_input_bps"`
	AvgOutputPps  float64 `json:"avg_output_pps"`
	AvgOutputBps  float64 `json:"avg_output_bps"`
}

type CheckResult struct {
	Timestamp     time.Time `json:"timestamp"`
	Usage         float64   `json:"usage,omitempty"`
	Name          string    `json:"name,omitempty"`
	Device        string    `json:"device,omitempty"`
	Total         uint64    `json:"total,omitempty"`
	Free          uint64    `json:"free,omitempty"`
	Used          uint64    `json:"used,omitempty"`
	WriteBps      *float64  `json:"write_bps,omitempty"`
	ReadBps       *float64  `json:"read_bps,omitempty"`
	InputPps      *float64  `json:"input_pps,omitempty"`
	InputBps      *float64  `json:"input_bps,omitempty"`
	OutputPps     *float64  `json:"output_pps,omitempty"`
	OutputBps     *float64  `json:"output_bps,omitempty"`
	Peak          float64   `json:"peak,omitempty"`
	Avg           float64   `json:"avg,omitempty"`
	PeakWriteBps  float64   `json:"peak_write_bps,omitempty"`
	PeakReadBps   float64   `json:"peak_read_bps,omitempty"`
	AvgWriteBps   float64   `json:"avg_write_bps,omitempty"`
	AvgReadBps    float64   `json:"avg_read_bps,omitempty"`
	PeakInputPps  float64   `json:"peak_input_pps,omitempty"`
	PeakInputBps  float64   `json:"peak_input_bps,omitempty"`
	PeakOutputPps float64   `json:"peak_output_pps,omitempty"`
	PeakOutputBps float64   `json:"peak_output_bps,omitempty"`
	AvgInputPps   float64   `json:"avg_input_pps,omitempty"`
	AvgInputBps   float64   `json:"avg_input_bps,omitempty"`
	AvgOutputPps  float64   `json:"avg_output_pps,omitempty"`
	AvgOutputBps  float64   `json:"avg_output_bps,omitempty"`
}

type MetricData struct {
	Type CheckType     `json:"type"`
	Data []CheckResult `json:"data,omitempty"`
}

type CheckBuffer struct {
	SuccessQueue chan MetricData
	FailureQueue chan MetricData
	Capacity     int
}
