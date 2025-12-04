package group

import (
	"context"
	"fmt"
	"strconv"

	"github.com/alpacax/alpamon/pkg/executor/handlers/common"
	"github.com/alpacax/alpamon/pkg/utils"
	"github.com/rs/zerolog/log"
)

// GroupHandler handles group management commands
type GroupHandler struct {
	*common.BaseHandler
}

// NewGroupHandler creates a new group handler
func NewGroupHandler(cmdExecutor common.CommandExecutor) *GroupHandler {
	h := &GroupHandler{
		BaseHandler: common.NewBaseHandler(
			common.Group,
			[]common.CommandType{
				common.AddGroup,
				common.DelGroup,
			},
			cmdExecutor,
		),
	}
	return h
}

// Execute runs the group management command
func (h *GroupHandler) Execute(ctx context.Context, cmd string, args *common.CommandArgs) (int, string, error) {
	switch cmd {
	case common.AddGroup.String():
		return h.handleAddGroup(ctx, args)
	case common.DelGroup.String():
		return h.handleDelGroup(ctx, args)
	default:
		return 1, "", fmt.Errorf("unknown group command: %s", cmd)
	}
}

// Validate checks if the arguments are valid for the command
func (h *GroupHandler) Validate(cmd string, args *common.CommandArgs) error {
	switch cmd {
	case common.AddGroup.String():
		data := GroupData{
			Groupname: args.Groupname,
			GID:       args.GID,
		}
		return h.ValidateStruct(data)

	case common.DelGroup.String():
		data := DeleteGroupData{
			Groupname: args.Groupname,
		}
		return h.ValidateStruct(data)

	default:
		return fmt.Errorf("unknown group command: %s", cmd)
	}
}

// handleAddGroup handles the addgroup command
func (h *GroupHandler) handleAddGroup(ctx context.Context, args *common.CommandArgs) (int, string, error) {
	// Extract arguments
	groupname := args.Groupname
	gid := int(args.GID)

	// Validate
	err := h.Validate(common.AddGroup.String(), args)
	if err != nil {
		return 1, err.Error(), nil
	}

	log.Info().
		Str("groupname", groupname).
		Uint64("gid", uint64(gid)).
		Msg("Adding group")

	var exitCode int
	var output string
	// Platform-specific group addition
	if utils.PlatformLike == "debian" {
		exitCode, output, err = h.Executor.Run(
			ctx,
			"/usr/sbin/addgroup",
			"--gid", strconv.Itoa(gid),
			groupname,
		)
		if exitCode != 0 {
			return exitCode, output, err
		}
	} else if utils.PlatformLike == "rhel" {
		exitCode, output, err = h.Executor.Run(
			ctx,
			"/usr/sbin/groupadd",
			"--gid", strconv.Itoa(gid),
			groupname,
		)
		if exitCode != 0 {
			return exitCode, output, err
		}
	} else {
		return 1, fmt.Sprintf("Platform '%s' not supported for group management", utils.PlatformLike), nil
	}

	log.Info().
		Str("groupname", groupname).
		Uint64("gid", uint64(gid)).
		Int("exitCode", exitCode).
		Msg("Group added successfully")

	return exitCode, fmt.Sprintf("Group '%s' added successfully with GID %d", groupname, gid), nil
}

// handleDelGroup handles the delgroup command
func (h *GroupHandler) handleDelGroup(ctx context.Context, args *common.CommandArgs) (int, string, error) {
	// Extract arguments
	groupname := args.Groupname

	// Validate
	err := h.Validate(common.DelGroup.String(), args)
	if err != nil {
		return 1, err.Error(), nil
	}

	log.Info().
		Str("groupname", groupname).
		Msg("Deleting group")

	var exitCode int
	var output string

	// Platform-specific group deletion
	if utils.PlatformLike == "debian" {
		exitCode, output, err = h.Executor.Run(
			ctx,
			"/usr/sbin/delgroup",
			groupname,
		)
		if exitCode != 0 {
			return exitCode, output, err
		}
	} else if utils.PlatformLike == "rhel" {
		exitCode, output, err = h.Executor.Run(
			ctx,
			"/usr/sbin/groupdel",
			groupname,
		)
		if exitCode != 0 {
			return exitCode, output, err
		}
	} else {
		return 1, fmt.Sprintf("Platform '%s' not supported for group management", utils.PlatformLike), nil
	}

	log.Info().
		Str("groupname", groupname).
		Int("exitCode", exitCode).
		Msg("Group deleted successfully")

	return exitCode, fmt.Sprintf("Group '%s' deleted successfully", groupname), nil
}
