//go:build !windows

package pidfile

import "syscall"

// isProcess uses kill -0 to check whether a process is running.
func isProcess(pid int) bool {
	return syscall.Kill(pid, 0) == nil
}
