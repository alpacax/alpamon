//go:build !windows

package utils

import (
	"fmt"
	"os"
	"os/user"
	"strconv"
	"syscall"

	"github.com/rs/zerolog/log"
)

// ResolveGroups builds the supplementary group list for Credential.Groups,
// applying the current platform's setgroups(2) cap. It is the single entry
// point shared by every privilege-demotion path (Demote and the websh PTY),
// so group handling stays identical across them.
func ResolveGroups(gid uint32, groupIds []string) (groups []uint32, groupInList bool, err error) {
	return resolveGroups(gid, groupIds, maxSupplementaryGroups())
}

// resolveGroups builds the supplementary group list for Credential.Groups.
// The primary gid is placed first so it survives truncation, and the requested
// gid's membership is reported via groupInList for ValidateGroup. When
// maxGroups > 0 the list is capped to that many entries.
func resolveGroups(gid uint32, groupIds []string, maxGroups int) (groups []uint32, groupInList bool, err error) {
	groups = make([]uint32, 0, len(groupIds)+1)
	groups = append(groups, gid)
	for _, gidStr := range groupIds {
		gidUint, err := strconv.ParseUint(gidStr, 10, 32)
		if err != nil {
			return nil, false, err
		}
		if uint32(gidUint) == gid {
			groupInList = true
			continue
		}
		groups = append(groups, uint32(gidUint))
	}
	if maxGroups > 0 && len(groups) > maxGroups {
		groups = groups[:maxGroups]
	}
	return groups, groupInList, nil
}

// DemoteOptions configures the behavior of privilege demotion
type DemoteOptions struct {
	// ValidateGroup checks if the specified group is in the user's group list
	ValidateGroup bool
}

// DemoteResult contains the result of privilege demotion
type DemoteResult struct {
	// SysProcAttr contains the credentials for privilege demotion
	SysProcAttr *syscall.SysProcAttr
	// User contains the looked up user information
	User *user.User
}

// Demote creates syscall attributes for privilege demotion to the specified user/group.
// If username or groupname is empty, or if not running as root, returns nil without error.
// When ValidateGroup is true, returns an error if the group is not in the user's group list.
func Demote(username, groupname string, opts DemoteOptions) (*DemoteResult, error) {
	if username == "" || groupname == "" {
		log.Debug().Msg("No username or groupname provided, running as the current user.")
		return nil, nil
	}

	if os.Getuid() != 0 {
		log.Warn().Msg("Not running as root. Falling back to the current user.")
		return nil, nil
	}

	usr, err := user.Lookup(username)
	if err != nil {
		return nil, fmt.Errorf("there is no corresponding %s username in this server", username)
	}

	grp, err := user.LookupGroup(groupname)
	if err != nil {
		return nil, fmt.Errorf("there is no corresponding %s groupname in this server", groupname)
	}

	uid, err := strconv.ParseUint(usr.Uid, 10, 32)
	if err != nil {
		return nil, err
	}

	gid, err := strconv.ParseUint(grp.Gid, 10, 32)
	if err != nil {
		return nil, err
	}

	groupIds, err := usr.GroupIds()
	if err != nil {
		return nil, err
	}

	groups, groupInList, err := ResolveGroups(uint32(gid), groupIds)
	if err != nil {
		return nil, err
	}

	if opts.ValidateGroup && !groupInList {
		return nil, fmt.Errorf("groupname %s is not in user %s's group list", groupname, username)
	}

	log.Debug().Msgf("Demote permission to match user: %s, group: %s.", username, groupname)

	return &DemoteResult{
		SysProcAttr: &syscall.SysProcAttr{
			Credential: &syscall.Credential{
				Uid:    uint32(uid),
				Gid:    uint32(gid),
				Groups: groups,
			},
		},
		User: usr,
	}, nil
}
