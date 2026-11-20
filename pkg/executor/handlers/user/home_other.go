//go:build !linux

package user

import (
	"errors"
	"os"
)

func renameHome(_, _ string) error {
	return errors.New("archiving home directories requires Linux")
}

func fileOwnerUID(_ os.FileInfo) (uint64, error) {
	return 0, errors.New("home ownership checks require Linux")
}
