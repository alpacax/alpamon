//go:build !windows

package updater

// CleanupStaleOld is a no-op on Unix. Unix's os.Rename can replace a
// running executable in place, so the ".old" staging file created by
// the Windows updater does not exist here.
func CleanupStaleOld() {}
