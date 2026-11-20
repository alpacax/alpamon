//go:build !linux

package user

import (
	"context"
	"errors"
	"os"
	"os/user"
)

func homeRootMountID(*os.File) (uint64, error) { return 0, nil }

func (unsupportedAccountLocker) archiveHome(context.Context, *user.User, DeleteUserData) (string, error) {
	return "", errors.New("archive_refused: archiving home directories requires Linux")
}

func (unsupportedAccountLocker) clearPendingArchive(string) error { return nil }
