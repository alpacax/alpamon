//go:build !linux

package user

import (
	"context"
	"errors"
	"os/user"
)

func (unsupportedAccountLocker) archiveHome(context.Context, *user.User, DeleteUserData) (string, error) {
	return "", errors.New("archive_refused: archiving home directories requires Linux")
}

func (unsupportedAccountLocker) clearPendingArchive(string) error { return nil }
