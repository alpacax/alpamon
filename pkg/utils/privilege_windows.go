package utils

import (
	"os/user"
	"syscall"

	"github.com/rs/zerolog/log"
)

// DemoteOptions configures the behavior of privilege demotion
type DemoteOptions struct {
	ValidateGroup bool
}

// DemoteResult contains the result of privilege demotion
type DemoteResult struct {
	SysProcAttr *syscall.SysProcAttr
	User        *user.User
}

// Demote is a no-op on Windows. Windows does not support Unix-style
// credential demotion via setuid/setgid.
func Demote(username, groupname string, opts DemoteOptions) (*DemoteResult, error) {
	if username == "" || groupname == "" {
		log.Debug().Msg("No username or groupname provided, running as the current user.")
		return nil, nil
	}
	log.Debug().Msg("Privilege demotion is not supported on Windows, running as the current user.")
	return nil, nil
}
