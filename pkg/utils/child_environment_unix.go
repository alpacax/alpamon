//go:build !windows

package utils

import (
	"fmt"
	"os"
	"os/user"
	"strconv"
	"syscall"
)

// ProcessChildEnvironment resolves the identity selected by attr before building its environment.
func ProcessChildEnvironment(attr *syscall.SysProcAttr) ([]string, error) {
	uid := strconv.Itoa(os.Geteuid())
	if attr != nil && attr.Credential != nil {
		uid = strconv.FormatUint(uint64(attr.Credential.Uid), 10)
	}
	return processChildEnvironment(uid, user.LookupId)
}

func processChildEnvironment(uid string, lookup func(string) (*user.User, error)) ([]string, error) {
	usr, err := lookup(uid)
	if err != nil {
		if uid == strconv.Itoa(os.Geteuid()) {
			return MinimalChildEnvironment("/", ""), nil
		}
		return nil, fmt.Errorf("resolve child user: %w", err)
	}
	return MinimalChildEnvironment(usr.HomeDir, usr.Username), nil
}
