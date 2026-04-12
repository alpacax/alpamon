//go:build !windows

package runner

import (
	"os"
	"syscall"

	"github.com/rs/zerolog/log"
)

// terminateProcess sends SIGTERM to the process group, falling back to SIGKILL.
func terminateProcess(p *os.Process) error {
	if err := syscall.Kill(-p.Pid, syscall.SIGTERM); err != nil {
		log.Debug().Err(err).Msg("SIGTERM failed, trying SIGKILL.")
		return syscall.Kill(-p.Pid, syscall.SIGKILL)
	}
	return nil
}
