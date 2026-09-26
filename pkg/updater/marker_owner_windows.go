package updater

import (
	"errors"
	"os"

	"github.com/alpacax/alpamon/v2/pkg/utils"
)

// checkMarkerOwner accepts a regular-file marker owned by SYSTEM or the
// Administrators group.
func checkMarkerOwner(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return errors.New("upgrade marker is not a regular file")
	}
	ok, err := utils.OwnedByAdministrators(path)
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("upgrade marker is not owned by SYSTEM or Administrators")
	}
	return nil
}
