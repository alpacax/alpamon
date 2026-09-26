package updater

import (
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

// restoreBinary puts the rollback copy back in place. The running executable
// cannot be overwritten, so it is moved aside to ".old" first, as the swap
// does; CleanupStaleOld removes it on the next start.
func restoreBinary(rollbackPath, currentPath string) error {
	oldPath := currentPath + ".old"
	_ = os.Remove(oldPath)
	if err := moveFileEx(currentPath, oldPath, windows.MOVEFILE_REPLACE_EXISTING); err != nil {
		return fmt.Errorf("failed to move running binary aside: %w", err)
	}
	if err := moveFileEx(rollbackPath, currentPath, windows.MOVEFILE_REPLACE_EXISTING); err != nil {
		if rbErr := moveFileEx(oldPath, currentPath, windows.MOVEFILE_REPLACE_EXISTING); rbErr != nil {
			// Last resort so a binary is always in place: copy, not move.
			if cpErr := copyFile(oldPath, currentPath, 0o755); cpErr != nil {
				return fmt.Errorf("failed to restore the previous binary (%v), to put the current one back (%v) and to copy it back (%v)", err, rbErr, cpErr)
			}
		}
		return fmt.Errorf("failed to restore the previous binary: %w", err)
	}
	return nil
}
