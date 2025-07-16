package net

import (
	"github.com/alpacax/alpamon/pkg/collector/check/base"
	"github.com/shirou/gopsutil/v4/net"
)

func NewCheck(args *base.CheckArgs) base.CheckStrategy {
	var check base.CheckStrategy
	switch args.Type {
	case base.NET_COLLECTOR:
		check = &CollectCheck{
			BaseCheck:  base.NewBaseCheck(args),
			lastMetric: make(map[string]net.IOCountersStat),
		}
	case base.NET:
		check = &SendCheck{
			BaseCheck: base.NewBaseCheck(args),
		}
	}

	return check
}
