package updater

import (
	"fmt"
	"os"

	"github.com/rs/zerolog/log"
	"golang.org/x/sys/windows"
)

// Windows cannot overwrite a running .exe via os.Rename because the
// file is locked while the process holds it open. The standard self-
// update trick is to rename the current binary to a sibling ".old"
// path first (Windows does allow renaming a running binary) and then
// drop the new binary in its place. The .old file is cleaned up on
// the next restart via CleanupStaleOld; if the process is killed
// before that, MOVEFILE_DELAY_UNTIL_REBOOT is used as a backstop so
// reboot eventually removes it.
func replaceBinary(newPath, currentPath string) error {
	info, err := os.Stat(currentPath)
	if err != nil {
		return fmt.Errorf("failed to stat current binary: %w", err)
	}

	// Stage the new binary next to the current one so the final step
	// is a rename on the same volume.
	stagePath := currentPath + ".new"
	if err := copyFile(newPath, stagePath, info.Mode()); err != nil {
		return fmt.Errorf("failed to stage new binary: %w", err)
	}
	defer func() { _ = os.Remove(stagePath) }()

	// 1. Move the currently-running binary out of the way.
	oldPath := currentPath + ".old"
	// Best-effort remove any stale .old from a prior update; if the
	// old one is still locked, MoveFileEx with REPLACE_EXISTING
	// below will fail and we'll surface a clear error.
	_ = os.Remove(oldPath)
	if err := moveFileEx(currentPath, oldPath, windows.MOVEFILE_REPLACE_EXISTING); err != nil {
		return fmt.Errorf("failed to move running binary aside: %w", err)
	}

	// 2. Put the new binary in place.
	if err := moveFileEx(stagePath, currentPath, windows.MOVEFILE_REPLACE_EXISTING); err != nil {
		// Roll back: put the old binary back under its original name.
		// A stale partial file at currentPath may still be present
		// (e.g., AV held it open); try to remove before the rename so
		// we don't fight the same sharing violation twice.
		_ = os.Remove(currentPath)
		if rbErr := moveFileEx(oldPath, currentPath, windows.MOVEFILE_REPLACE_EXISTING); rbErr != nil {
			return fmt.Errorf("failed to install new binary (%v) and rollback failed (%v); manual recovery: rename %s back to %s", err, rbErr, oldPath, currentPath)
		}
		return fmt.Errorf("failed to install new binary: %w", err)
	}

	// 3. Schedule the .old file for removal on next reboot as a
	// backstop in case the startup cleanup never runs.
	if err := moveFileEx(oldPath, "", windows.MOVEFILE_DELAY_UNTIL_REBOOT); err != nil {
		log.Warn().Err(err).Str("path", oldPath).
			Msg("Could not schedule delete-on-reboot for the old binary; it will be cleaned up on next alpamon start.")
	}

	log.Debug().Str("old", oldPath).Msg("Windows binary replaced; old exe will be cleaned up later.")
	return nil
}

// moveFileEx wraps the Windows MoveFileExW syscall.
// If newPath is empty, the Windows API uses a NULL pointer, which
// combined with MOVEFILE_DELAY_UNTIL_REBOOT schedules oldPath for
// deletion on reboot.
func moveFileEx(oldPath, newPath string, flags uint32) error {
	oldPtr, err := windows.UTF16PtrFromString(oldPath)
	if err != nil {
		return err
	}
	var newPtr *uint16
	if newPath != "" {
		newPtr, err = windows.UTF16PtrFromString(newPath)
		if err != nil {
			return err
		}
	}
	if err := windows.MoveFileEx(oldPtr, newPtr, flags); err != nil {
		return fmt.Errorf("MoveFileEx(%q, %q, 0x%x): %w", oldPath, newPath, flags, err)
	}
	return nil
}
