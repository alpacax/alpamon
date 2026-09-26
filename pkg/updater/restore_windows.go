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
			return fmt.Errorf("failed to restore the previous binary (%v) and to put the current one back (%v)", err, rbErr)
		}
		return fmt.Errorf("failed to restore the previous binary: %w", err)
	}
	return nil
}
