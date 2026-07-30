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

// DemotedSysProcAttr is the single entry point for demotions that keep the
// user's supplementary groups (Demote, Websh PTY, code-server): one place for
// setgroups(2) capping, so those paths cannot drift. Demotions that must drop
// the group list build their own Credential with Groups left nil.
func DemotedSysProcAttr(uid, gid uint32, groupIds []string) (attr *syscall.SysProcAttr, groupInList bool, err error) {
	groups, groupInList, err := resolveGroups(gid, groupIds, maxSupplementaryGroups())
	if err != nil {
		return nil, false, err
	}
	return &syscall.SysProcAttr{
		Credential: &syscall.Credential{
			Uid:    uid,
			Gid:    gid,
			Groups: groups,
		},
	}, groupInList, nil
}

// resolveGroups builds the supplementary group list for Credential.Groups.
// The primary gid is placed first so it survives truncation, and the requested
// gid's membership is reported via groupInList for ValidateGroup. Duplicates are
// dropped before capping so a repeated gid cannot push a distinct one out. When
// maxGroups > 0 the list is capped to that many entries.
func resolveGroups(gid uint32, groupIds []string, maxGroups int) (groups []uint32, groupInList bool, err error) {
	groups = make([]uint32, 0, len(groupIds)+1)
	groups = append(groups, gid)
	seen := map[uint32]struct{}{gid: {}}
	for _, gidStr := range groupIds {
		gidUint, err := strconv.ParseUint(gidStr, 10, 32)
		if err != nil {
			return nil, false, fmt.Errorf("invalid supplementary group id: %w", err)
		}
		group := uint32(gidUint)
		if group == gid {
			groupInList = true
		}
		if _, dup := seen[group]; dup {
			continue
		}
		seen[group] = struct{}{}
		groups = append(groups, group)
	}
	if maxGroups > 0 && len(groups) > maxGroups {
		// Warn, not Debug: the process silently loses file access it was granted,
		// and Debug is off in production (config.go sets InfoLevel).
		log.Warn().Int("requested", len(groups)).Int("cap", maxGroups).
			Msg("Supplementary group list truncated to the platform setgroups limit.")
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

	sysProcAttr, groupInList, err := DemotedSysProcAttr(uint32(uid), uint32(gid), groupIds)
	if err != nil {
		return nil, err
	}

	if opts.ValidateGroup && !groupInList {
		return nil, fmt.Errorf("groupname %s is not in user %s's group list", groupname, username)
	}

	log.Debug().Msgf("Demote permission to match user: %s, group: %s.", username, groupname)

	return &DemoteResult{
		SysProcAttr: sysProcAttr,
		User:        usr,
	}, nil
}
