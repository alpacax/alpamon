//go:build !windows

package updater

// ensureSelfRestartable is a no-op on Unix. restartAgent execs in place,
// so no external restarter is needed.
func ensureSelfRestartable() error { return nil }
