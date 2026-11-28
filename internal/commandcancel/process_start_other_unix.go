//go:build !linux && !windows

package commandcancel

import "github.com/shirou/gopsutil/v4/process"

// ProcessStartTime returns the process start time in Unix epoch milliseconds.
func ProcessStartTime(pid int) (int64, error) {
	p, err := process.NewProcess(int32(pid))
	if err != nil {
		return 0, err
	}
	return p.CreateTime()
}
