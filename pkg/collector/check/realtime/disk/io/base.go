package diskio

import (
	"github.com/alpacax/alpamon/pkg/collector/check/base"
	"github.com/shirou/gopsutil/v4/disk"
)

func NewCheck(args *base.CheckArgs) base.CheckStrategy {
	var check base.CheckStrategy
	switch args.Type {
	case base.DiskIOCollector:
		check = &CollectCheck{
			BaseCheck:  base.NewBaseCheck(args),
			lastMetric: make(map[string]disk.IOCountersStat),
		}
	case base.DiskIO:
		check = &SendCheck{
			BaseCheck: base.NewBaseCheck(args),
		}
	}

	return check
}
