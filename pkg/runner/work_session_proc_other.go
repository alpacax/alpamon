//go:build !windows && !darwin

package runner

import (
	"slices"

	"github.com/shirou/gopsutil/v4/process"
)

// processState reads the state of pid from the process table.
func processState(pid int) (procState, error) {
	p, err := process.NewProcess(int32(pid))
	if err != nil {
		return procRunning, err
	}
	statuses, err := p.Status()
	if err != nil {
		return procRunning, err
	}
	switch {
	case slices.Contains(statuses, process.Zombie):
		return procZombie, nil
	case slices.Contains(statuses, process.Stop):
		return procStopped, nil
	}
	return procRunning, nil
}
