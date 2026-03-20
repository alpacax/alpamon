package transporter

import (
	"fmt"

	"github.com/alpacax/alpamon/pkg/collector/check/base"
)

const (
	cpuURL             string = "/api/metrics/realtime/cpu/"
	hourlyCPUUsageURL  string = "/api/metrics/hourly/cpu/"
	dailyCPUUsageURL   string = "/api/metrics/daily/cpu/"
	memURL             string = "/api/metrics/realtime/memory/"
	hourlyMemUsageURL  string = "/api/metrics/hourly/memory/"
	dailyMemUsageURL   string = "/api/metrics/daily/memory/"
	diskUsageURL       string = "/api/metrics/realtime/disk-usage/"
	hourlyDiskUsageURL string = "/api/metrics/hourly/disk-usage/"
	dailyDiskUsageURL  string = "/api/metrics/daily/disk-usage/"
	diskIOURL          string = "/api/metrics/realtime/disk-io/"
	hourlyDiskIOURL    string = "/api/metrics/hourly/disk-io/"
	dailyDiskIOURL     string = "/api/metrics/daily/disk-io/"
	netURL             string = "/api/metrics/realtime/traffic/"
	hourlyNetURL       string = "/api/metrics/hourly/traffic/"
	dailyNetURL        string = "/api/metrics/daily/traffic/"
)

type URLResolver struct {
	checkTypeToURL map[base.CheckType]string
}

func NewURLResolver() *URLResolver {
	return &URLResolver{
		checkTypeToURL: map[base.CheckType]string{
			base.CPU:             cpuURL,
			base.HourlyCPUUsage: hourlyCPUUsageURL,
			base.DailyCPUUsage:  dailyCPUUsageURL,
			base.Mem:             memURL,
			base.HourlyMemUsage: hourlyMemUsageURL,
			base.DailyMemUsage:  dailyMemUsageURL,
			base.DiskUsage:       diskUsageURL,
			base.HourlyDiskUsage: hourlyDiskUsageURL,
			base.DailyDiskUsage:  dailyDiskUsageURL,
			base.DiskIO:          diskIOURL,
			base.HourlyDiskIO:    hourlyDiskIOURL,
			base.DailyDiskIO:     dailyDiskIOURL,
			base.Net:             netURL,
			base.HourlyNet:       hourlyNetURL,
			base.DailyNet:        dailyNetURL,
		},
	}
}

func (r *URLResolver) ResolveURL(checkType base.CheckType) (string, error) {
	url, exists := r.checkTypeToURL[checkType]
	if !exists {
		return "", fmt.Errorf("unknown check type: %s", checkType)
	}

	return url, nil
}
