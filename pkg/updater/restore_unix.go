//go:build !windows

package updater

import (
	"os"
	"path/filepath"
)

// restoreBinary puts the rollback copy back in place. Rename is atomic and
// allowed over a running executable on Unix.
func restoreBinary(rollbackPath, currentPath string) error {
	if err := os.Rename(rollbackPath, currentPath); err != nil {
		return err
	}
	return syncDir(filepath.Dir(currentPath))
}
