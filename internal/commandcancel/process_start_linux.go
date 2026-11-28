package commandcancel

import "github.com/tklauser/go-sysconf"

var nativeProcessStart = processStartReader{
	procRoot: "/proc",
	clockTicks: func() (uint64, error) {
		ticks, err := sysconf.Sysconf(sysconf.SC_CLK_TCK)
		if err != nil {
			return 0, err
		}
		if ticks <= 0 {
			return 0, nil
		}
		return uint64(ticks), nil
	},
}

// ProcessStartTime returns the process start time in Unix epoch milliseconds.
func ProcessStartTime(pid int) (int64, error) {
	return nativeProcessStart.startTime(pid)
}
