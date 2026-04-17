package updater

import (
	"os"

	"github.com/rs/zerolog/log"
)

// CleanupStaleOld removes the ".old" copy of the current executable
// left behind by a previous self-update. Windows cannot delete a
// running .exe, so the updater renames the running binary aside and
// relies on the next startup (or reboot) to clean it up.
//
// Safe to call unconditionally at startup; no-op when the file is
// absent.
func CleanupStaleOld() {
	exe, err := os.Executable()
	if err != nil {
		return
	}
	oldPath := exe + ".old"
	info, err := os.Stat(oldPath)
	if err != nil {
		return
	}
	if info.IsDir() {
		return
	}
	if err := os.Remove(oldPath); err != nil {
		log.Debug().Err(err).Str("path", oldPath).
			Msg("Could not remove stale .old binary; reboot will clear it.")
		return
	}
	log.Debug().Str("path", oldPath).Msg("Removed stale .old binary.")
}
