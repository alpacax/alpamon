//go:build !linux && !darwin

package runner

import "github.com/shirou/gopsutil/v4/process"

func sudoProcessStart(pid int) uint64 {
	proc, err := process.NewProcess(int32(pid))
	if err != nil {
		return 0
	}
	start, err := proc.CreateTime()
	if err != nil || start <= 0 {
		return 0
	}
	return uint64(start)
}
