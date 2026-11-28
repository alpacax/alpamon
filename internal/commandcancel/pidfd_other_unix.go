//go:build !linux && !windows

package commandcancel

// systemPidfd is nil: this host has no handle that holds a process through
// signal delivery.
func systemPidfd() *pidfdOps {
	return nil
}
