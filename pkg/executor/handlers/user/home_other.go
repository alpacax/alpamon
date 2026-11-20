//go:build !linux

package user

import (
	"context"
	"errors"
	"os"
	"os/user"
)

func (unsupportedAccountLocker) archiveHome(context.Context, *user.User, DeleteUserData) (string, error) {
	return "", errors.New("archive_refused: archiving home directories requires Linux")
}

func fileOwnerUID(_ os.FileInfo) (uint64, error) {
	return 0, errors.New("home ownership checks require Linux")
}

func (unsupportedAccountLocker) clearPendingArchive(string) error { return nil }
