//go:build !linux

package user

import (
	"context"

	"github.com/alpacax/alpamon/v2/pkg/executor/handlers/common"
)

type unsupportedAccountLocker struct{}

func newAccountLocker(*UserHandler) accountLocker { return unsupportedAccountLocker{} }

func (unsupportedAccountLocker) execute(context.Context, string, *common.CommandArgs) (int, string, error) {
	return 1, "unsupported_platform: account locking requires Linux", nil
}

// NewUnsupportedAccountLockHandler registers the Linux-only command refusals.
func NewUnsupportedAccountLockHandler(executor common.CommandExecutor) *UserHandler {
	h := NewUserHandler(executor, nil, nil)
	h.BaseHandler = common.NewBaseHandler(common.User, []common.CommandType{common.LockUser, common.UnlockUser}, executor)
	return h
}

func (unsupportedAccountLocker) forget(string) error { return nil }
