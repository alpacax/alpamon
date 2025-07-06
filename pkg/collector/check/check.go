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
	base.HOURLY_CPU_USAGE:  hourlycpu.NewCheck,
	base.DAILY_CPU_USAGE:   dailycpu.NewCheck,
	base.MEM:               memory.NewCheck,
	base.HOURLY_MEM_USAGE:  hourlymemory.NewCheck,
	base.DAILY_MEM_USAGE:   dailymemory.NewCheck,
	base.DISK_USAGE:        diskusage.NewCheck,
	base.HOURLY_DISK_USAGE: hourlydiskusage.NewCheck,
	base.DAILY_DISK_USAGE:  dailydiskusage.NewCheck,
	base.DISK_IO:           diskio.NewCheck,
	base.DISK_IO_COLLECTOR: diskio.NewCheck,
	base.HOURLY_DISK_IO:    hourlydiskio.NewCheck,
	base.DAILY_DISK_IO:     dailydiskio.NewCheck,
	base.NET:               net.NewCheck,
	base.NET_COLLECTOR:     net.NewCheck,
	base.HOURLY_NET:        hourlynet.NewCheck,
	base.DAILY_NET:         dailynet.NewCheck,
	base.CLEANUP:           cleanup.NewCheck,
	base.ALERT:             alert.NewCheck,
	base.STATUS:            status.NewCheck,
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
