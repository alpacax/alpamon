//go:build !linux && !darwin && !windows

package commandcancel

import (
	"slices"
	"time"

	"github.com/shirou/gopsutil/v4/process"
)

func WaitExited(pid int) error {
	p, err := process.NewProcess(int32(pid))
	if err != nil {
		return err
	}
	for {
		statuses, err := p.Status()
		if err != nil {
			return err
		}
		if slices.Contains(statuses, process.Zombie) {
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
}
