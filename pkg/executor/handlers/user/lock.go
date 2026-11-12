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
}

func validateLockUser(args *common.CommandArgs) error {
	if args == nil || args.Username == "" {
		return fmt.Errorf("invalid_username: username is required")
	}
	if strings.HasPrefix(args.Username, "-") || strings.ContainsAny(args.Username, "/:\x00\r\n\t ") || args.Username == "." || args.Username == ".." {
		return fmt.Errorf("invalid_username: invalid local account name")
	}
	return nil
}
