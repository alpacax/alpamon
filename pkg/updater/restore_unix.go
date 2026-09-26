//go:build !windows

package updater

import (
	"os"
	"path/filepath"

	"github.com/rs/zerolog/log"
)

// restoreBinary puts the rollback copy back in place. Rename is atomic and
// allowed over a running executable on Unix.
func restoreBinary(rollbackPath, currentPath string) error {
	if err := os.Rename(rollbackPath, currentPath); err != nil {
		return err
	}
	// The rollback copy is consumed; the restore has happened and must be
	// followed through, so a failed directory sync is only logged.
	if err := syncDir(filepath.Dir(currentPath)); err != nil {
		log.Warn().Err(err).Msg("Restored the previous binary, but the directory sync failed.")
	}
	return nil
}
