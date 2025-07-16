package transporter

import (
	"fmt"

	"github.com/alpacax/alpamon/pkg/collector/check/base"
)

const (
	CPU               string = "/api/metrics/realtime/cpu/"
	HOURLY_CPU_USAGE  string = "/api/metrics/hourly/cpu/"
	DAILY_CPU_USAGE   string = "/api/metrics/daily/cpu/"
	MEM               string = "/api/metrics/realtime/memory/"
	HOURLY_MEM_USAGE  string = "/api/metrics/hourly/memory/"
	DAILY_MEM_USAGE   string = "/api/metrics/daily/memory/"
	DISK_USAGE        string = "/api/metrics/realtime/disk-usage/"
	HOURLY_DISK_USAGE string = "/api/metrics/hourly/disk-usage/"
	DAILY_DISK_USAGE  string = "/api/metrics/daily/disk-usage/"
	DISK_IO           string = "/api/metrics/realtime/disk-io/"
	HOURLY_DISK_IO    string = "/api/metrics/hourly/disk-io/"
	DAILY_DISK_IO     string = "/api/metrics/daily/disk-io/"
	NET               string = "/api/metrics/realtime/traffic/"
	HOURLY_NET        string = "/api/metrics/hourly/traffic/"
	DAILY_NET         string = "/api/metrics/daily/traffic/"
)

type URLResolver struct {
	checkTypeToURL map[base.CheckType]string
}

func NewURLResolver() *URLResolver {
	return &URLResolver{
		checkTypeToURL: map[base.CheckType]string{
			base.CPU:               CPU,
			base.HOURLY_CPU_USAGE:  HOURLY_CPU_USAGE,
			base.DAILY_CPU_USAGE:   DAILY_CPU_USAGE,
			base.MEM:               MEM,
			base.HOURLY_MEM_USAGE:  HOURLY_MEM_USAGE,
			base.DAILY_MEM_USAGE:   DAILY_MEM_USAGE,
			base.DISK_USAGE:        DISK_USAGE,
			base.HOURLY_DISK_USAGE: HOURLY_DISK_USAGE,
			base.DAILY_DISK_USAGE:  DAILY_DISK_USAGE,
			base.DISK_IO:           DISK_IO,
			base.HOURLY_DISK_IO:    HOURLY_DISK_IO,
			base.DAILY_DISK_IO:     DAILY_DISK_IO,
			base.NET:               NET,
			base.HOURLY_NET:        HOURLY_NET,
			base.DAILY_NET:         DAILY_NET,
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
