package group

import (
	"context"
	"fmt"
	"strconv"

	"github.com/alpacax/alpamon/v2/pkg/executor/handlers/common"
	"github.com/alpacax/alpamon/v2/pkg/utils"
	"github.com/rs/zerolog/log"
)

// GroupHandler handles group management commands
type GroupHandler struct {
	*common.BaseHandler
	syncManager common.SystemInfoManager
	// lookupGroup verifies existence before creating (idempotency gate). It
	// defaults to an os/user-backed implementation and is overridden in tests.
	// See pkg/executor/handlers/common/lookup.go.
	lookupGroup common.GroupLookupFunc
}

// NewGroupHandler creates a new group handler
func NewGroupHandler(cmdExecutor common.CommandExecutor, syncManager common.SystemInfoManager) *GroupHandler {
	h := &GroupHandler{
		BaseHandler: common.NewBaseHandler(
			common.Group,
			[]common.CommandType{
				common.AddGroup,
				common.DelGroup,
			},
			cmdExecutor,
		),
		syncManager: syncManager,
		lookupGroup: common.DefaultGroupLookup,
	}
	return h
}

// Execute runs the group management command
func (h *GroupHandler) Execute(ctx context.Context, cmd string, args *common.CommandArgs) (int, string, error) {
	ctx, cancel := common.WithHandlerTimeout(ctx, common.GroupTimeout)
	defer cancel()

	var exitCode int
	var output string
	var err error

	switch cmd {
	case common.AddGroup.String():
		exitCode, output, err = h.handleAddGroup(ctx, args)
	case common.DelGroup.String():
		exitCode, output, err = h.handleDelGroup(ctx, args)
	default:
		return 1, "", fmt.Errorf("unknown group command: %s", cmd)
	}

	if err != nil && common.IsTimeout(ctx) {
		return common.TimeoutError(common.GroupTimeout)
	}

	// Sync system info after successful command execution
	if exitCode == 0 && h.syncManager != nil {
		h.syncManager.SyncSystemInfo([]string{"groups", "users"})
	}

	return exitCode, output, err
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

	// Idempotency gate (M8): verify by lookup whether the group already exists
	// before attempting creation, so re-provisioning an already-present group
	// is a no-op instead of a hard addgroup/groupadd "already exists" failure.
	// A same-name/different-gid group is real drift and is surfaced, not masked.
	// The classifier is shared with the RHEL primary-group ensure in handleAddUser
	// so both paths behave identically (A-3 consistency).
	needCreate, code, out, err := common.ClassifyGroupForCreate(h.lookupGroup, groupname, args.GID)
	if code != 0 {
		return code, out, err
	}
	if !needCreate {
		// Group present with the expected gid: idempotent success. Returning 0
		// lets Execute still run SyncSystemInfo, reconciling DB<->reality drift.
		log.Info().
			Str("groupname", groupname).
			Uint64("gid", uint64(gid)).
			Msg("Group already exists with matching gid; skipping creation")
		return 0, fmt.Sprintf("Group '%s' already exists with GID %d", groupname, gid), nil
	}

	var createCode, exitCode int
	var output string
	// Platform-specific group addition
	switch utils.PlatformLike {
	case "debian":
		createCode, output, err = h.Executor.Run(
			ctx,
			"/usr/sbin/addgroup",
			"--gid", strconv.Itoa(gid),
			groupname,
		)
	case "rhel":
		createCode, output, err = h.Executor.Run(
			ctx,
			"/usr/sbin/groupadd",
			"--gid", strconv.Itoa(gid),
			groupname,
		)
	default:
		return 1, fmt.Sprintf("Platform '%s' not supported for group management", utils.PlatformLike), nil
	}

	// Secondary net: a raced or NSS-backed group invisible to the pure-Go
	// lookup above may cause a non-zero "already exists". Re-verify and treat a
	// matching group as idempotent success.
	exitCode, output, err = common.ReconcileGroupCreate(h.lookupGroup, groupname, args.GID, createCode, output, err)
	if exitCode != 0 {
		return exitCode, output, err
	}

	// A non-zero create that reconciled to success means the group already
	// existed (raced or NSS-backed); report it as such rather than "added".
	if createCode != 0 {
		log.Info().
			Str("groupname", groupname).
			Uint64("gid", uint64(gid)).
			Msg("Group already exists; reconciled to idempotent success")
		return 0, fmt.Sprintf("Group '%s' already exists with GID %d", groupname, gid), nil
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
	switch utils.PlatformLike {
	case "debian":
		exitCode, output, err = h.Executor.Run(
			ctx,
			"/usr/sbin/delgroup",
			groupname,
		)
		if exitCode != 0 {
			return exitCode, output, err
		}
	case "rhel":
		exitCode, output, err = h.Executor.Run(
			ctx,
			"/usr/sbin/groupdel",
			groupname,
		)
		if exitCode != 0 {
			return exitCode, output, err
		}
	default:
		return 1, fmt.Sprintf("Platform '%s' not supported for group management", utils.PlatformLike), nil
	}

	log.Info().
		Str("groupname", groupname).
		Int("exitCode", exitCode).
		Msg("Group deleted successfully")

	return exitCode, fmt.Sprintf("Group '%s' deleted successfully", groupname), nil
}
