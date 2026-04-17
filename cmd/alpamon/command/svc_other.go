//go:build !windows

package command

// runningAsWindowsService is the non-Windows stub. Always false so the
// normal interactive runAgent() path is taken.
func runningAsWindowsService() bool { return false }

// runService is a no-op on Unix; the Windows implementation hands
// control off to golang.org/x/sys/windows/svc.
func runService() {}
