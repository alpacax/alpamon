package runner

import "os"

// terminateProcess kills the process on Windows.
// Windows does not have Unix-style process groups or SIGTERM.
func terminateProcess(p *os.Process) error {
	return p.Kill()
}
