//go:build !linux && !darwin

package runner

import (
	"errors"

	"github.com/shirou/gopsutil/v4/process"
)

func sudoProcessStart(pid int) (uint64, bool) {
	proc, err := process.NewProcess(int32(pid))
	if err != nil {
		return 0, errors.Is(err, process.ErrorProcessNotRunning)
	}
	start, err := proc.CreateTime()
	if err != nil || start <= 0 {
		return 0, false
	}
	return uint64(start), false
}
