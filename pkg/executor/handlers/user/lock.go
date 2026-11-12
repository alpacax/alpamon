package user

import (
	"context"
	"fmt"
	"strings"

	"github.com/alpacax/alpamon/v2/pkg/executor/handlers/common"
)

// Serialize all user mutations so a concurrent deletion cannot replace a checked account.
var accountLockGate = make(chan struct{}, 1)

type accountLocker interface {
	execute(context.Context, string, *common.CommandArgs) (int, string, error)
	forget(string) error
}

func validateLockUser(args *common.CommandArgs) error {
	if args == nil || args.Username == "" {
		return fmt.Errorf("invalid_username: username is required")
	}
	if err := validateLockUserName(args.Username); err != nil {
		return err
	}
	if lockUserDataFromArgs(args).UID == nil {
		return fmt.Errorf("uid_required: uid is required")
	}
	return nil
}

func validateLockUserName(name string) error {
	if name == "" || strings.ContainsAny(name, "%\\\"") || strings.HasPrefix(name, "-") || strings.ContainsAny(name, "/:\x00\r\n\t ") || name == "." || name == ".." {
		return fmt.Errorf("invalid_username: invalid local account name")
	}
	return nil
}
