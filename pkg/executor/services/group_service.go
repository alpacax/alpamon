package services

import (
	"context"
	"fmt"
	"os/user"
	"strconv"
	"strings"

	"github.com/rs/zerolog/log"
)

// CommandExecutor interface defines the contract for executing system commands
// This is duplicated here to avoid circular dependency with handlers package
type CommandExecutor interface {
	Run(ctx context.Context, name string, args ...string) (exitCode int, output string, err error)
	RunAsUser(ctx context.Context, username string, name string, args ...string) (exitCode int, output string, err error)
	RunWithInput(ctx context.Context, input string, name string, args ...string) (exitCode int, output string, err error)
}

// GroupService provides group management operations for use by other handlers
type GroupService interface {
	// AddUserToGroups adds a user to one or more groups by GID
	AddUserToGroups(ctx context.Context, username string, gids []uint64) error
}

// DefaultGroupService is the default implementation of GroupService
type DefaultGroupService struct {
	executor CommandExecutor
}

// NewDefaultGroupService creates a new DefaultGroupService
func NewDefaultGroupService(executor CommandExecutor) *DefaultGroupService {
	return &DefaultGroupService{
		executor: executor,
	}
}

// AddUserToGroups adds a user to one or more groups by GID
func (s *DefaultGroupService) AddUserToGroups(ctx context.Context, username string, gids []uint64) error {
	if len(gids) == 0 {
		return nil
	}

	log.Info().
		Str("user", username).
		Uints64("gids", gids).
		Msg("Adding user to groups")

	// Convert GIDs to group names
	var groups []string
	for _, gid := range gids {
		group, err := user.LookupGroupId(strconv.FormatUint(gid, 10))
		if err != nil {
			log.Warn().Uint64("gid", gid).Err(err).Msg("Failed to lookup group by GID")
			continue
		}
		groups = append(groups, group.Name)
	}

	if len(groups) == 0 {
		return nil
	}

	// Use usermod -a -G to add user to groups
	// Join groups with comma for single command
	groupList := strings.Join(groups, ",")

	exitCode, output, _ := s.executor.RunAsUser(ctx, "root", "usermod", "-a", "-G", groupList, username)
	if exitCode != 0 {
		return fmt.Errorf("failed to add user %s to groups %v: %s", username, groups, output)
	}

	return nil
}
