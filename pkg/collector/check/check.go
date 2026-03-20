package check

import (
	"context"
	"fmt"

	"github.com/alpacax/alpamon/pkg/collector/check/base"
	cleanup "github.com/alpacax/alpamon/pkg/collector/check/batch/daily/cleanup"
	dailycpu "github.com/alpacax/alpamon/pkg/collector/check/batch/daily/cpu"
	dailydiskio "github.com/alpacax/alpamon/pkg/collector/check/batch/daily/disk/io"
	dailydiskusage "github.com/alpacax/alpamon/pkg/collector/check/batch/daily/disk/usage"
	dailymemory "github.com/alpacax/alpamon/pkg/collector/check/batch/daily/memory"
	dailynet "github.com/alpacax/alpamon/pkg/collector/check/batch/daily/net"
	hourlycpu "github.com/alpacax/alpamon/pkg/collector/check/batch/hourly/cpu"
	hourlydiskio "github.com/alpacax/alpamon/pkg/collector/check/batch/hourly/disk/io"
	hourlydiskusage "github.com/alpacax/alpamon/pkg/collector/check/batch/hourly/disk/usage"
	hourlymemory "github.com/alpacax/alpamon/pkg/collector/check/batch/hourly/memory"
	hourlynet "github.com/alpacax/alpamon/pkg/collector/check/batch/hourly/net"
	"github.com/alpacax/alpamon/pkg/collector/check/realtime/alert"
	"github.com/alpacax/alpamon/pkg/collector/check/realtime/cpu"
	diskio "github.com/alpacax/alpamon/pkg/collector/check/realtime/disk/io"
	diskusage "github.com/alpacax/alpamon/pkg/collector/check/realtime/disk/usage"
	"github.com/alpacax/alpamon/pkg/collector/check/realtime/memory"
	"github.com/alpacax/alpamon/pkg/collector/check/realtime/net"
	"github.com/alpacax/alpamon/pkg/collector/check/realtime/status"
)

var checkFactories = map[base.CheckType]newCheck{
	base.CPU:               cpu.NewCheck,
	base.HourlyCPUUsage:  hourlycpu.NewCheck,
	base.DailyCPUUsage:   dailycpu.NewCheck,
	base.Mem:               memory.NewCheck,
	base.HourlyMemUsage:  hourlymemory.NewCheck,
	base.DailyMemUsage:   dailymemory.NewCheck,
	base.DiskUsage:        diskusage.NewCheck,
	base.HourlyDiskUsage: hourlydiskusage.NewCheck,
	base.DailyDiskUsage:  dailydiskusage.NewCheck,
	base.DiskIO:           diskio.NewCheck,
	base.DiskIOCollector: diskio.NewCheck,
	base.HourlyDiskIO:    hourlydiskio.NewCheck,
	base.DailyDiskIO:     dailydiskio.NewCheck,
	base.Net:               net.NewCheck,
	base.NetCollector:     net.NewCheck,
	base.HourlyNet:        hourlynet.NewCheck,
	base.DailyNet:         dailynet.NewCheck,
	base.Cleanup:           cleanup.NewCheck,
	base.Alert:             alert.NewCheck,
	base.Status:            status.NewCheck,
}

type Check interface {
	Execute(ctx context.Context) error
}

type CheckFactory interface {
	CreateCheck(args *base.CheckArgs) (base.CheckStrategy, error)
}

type newCheck func(args *base.CheckArgs) base.CheckStrategy

type DefaultCheckFactory struct{}

func (f *DefaultCheckFactory) CreateCheck(args *base.CheckArgs) (base.CheckStrategy, error) {
	if factory, exists := checkFactories[args.Type]; exists {
		return factory(args), nil
	}

	return nil, fmt.Errorf("unknown check type: %s", args.Type)
}
