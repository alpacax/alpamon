//go:build windows

package user

import (
	"errors"
	"os"
)

func fileOwnerUID(_ os.FileInfo) (uint64, error) {
	return 0, errors.New("home ownership checks require a Unix host")
}
