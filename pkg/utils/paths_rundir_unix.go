//go:build !windows

package utils

import "os"

// RunDir returns the runtime directory for alpamon.
// When running as root (production), uses the system directory (e.g., /run/alpamon, /var/run/alpamon).
// When running as a regular user (development), uses /tmp/alpamon to avoid permission issues.
func RunDir() string {
	if os.Getuid() == 0 {
		return runDir()
	}
	return "/tmp/alpamon"
}
