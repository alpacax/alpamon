package user

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/alpacax/alpamon/pkg/executor/handlers/common"
	"github.com/alpacax/alpamon/pkg/executor/services"
	"github.com/alpacax/alpamon/pkg/utils"
	"github.com/rs/zerolog/log"
)

// UserHandler handles user management commands
type UserHandler struct {
	*common.BaseHandler
	groupService services.GroupService
	syncManager  common.SystemInfoManager
}

// NewUserHandler creates a new user handler
func NewUserHandler(cmdExecutor common.CommandExecutor, groupService services.GroupService, syncManager common.SystemInfoManager) *UserHandler {
	h := &UserHandler{
		BaseHandler: common.NewBaseHandler(
			common.User,
			[]common.CommandType{
				common.AddUser,
				common.DelUser,
				common.ModUser,
			},
			cmdExecutor,
		),
		groupService: groupService,
		syncManager:  syncManager,
	}
	return h
}

// Execute runs the user management command
func (h *UserHandler) Execute(ctx context.Context, cmd string, args *common.CommandArgs) (int, string, error) {
	// deluser with home backup may take longer
	timeout := common.UserTimeout
	if cmd == common.DelUser.String() {
		timeout = common.UserDeleteTimeout
	}
	ctx, cancel := common.WithHandlerTimeout(ctx, timeout)
	defer cancel()

	var exitCode int
	var output string
	var err error

	switch cmd {
	case common.AddUser.String():
		exitCode, output, err = h.handleAddUser(ctx, args)
	case common.DelUser.String():
		exitCode, output, err = h.handleDelUser(ctx, args)
	case common.ModUser.String():
		exitCode, output, err = h.handleModUser(ctx, args)
	default:
		return 1, "", fmt.Errorf("unknown user command: %s", cmd)
	}

	if err != nil && common.IsTimeout(ctx) {
		return common.TimeoutError(timeout)
	}

	// Sync system info after successful command execution
	if exitCode == 0 && h.syncManager != nil {
		h.syncManager.SyncSystemInfo([]string{"groups", "users"})
	}

	return exitCode, output, err
}

// Validate checks if the arguments are valid for the command
func (h *UserHandler) Validate(cmd string, args *common.CommandArgs) error {
	switch cmd {
	case common.AddUser.String():
		return h.ValidateStruct(userDataFromArgs(args))

	case common.DelUser.String():
		data := DeleteUserData{
			Username:           args.Username,
			PurgeHomeDirectory: args.PurgeHomeDirectory,
		}
		return h.ValidateStruct(data)

	case common.ModUser.String():
		data := ModUserData{
			Username:   args.Username,
			Groupnames: args.Groupnames,
			Comment:    args.Comment,
		}
		return h.ValidateStruct(data)

	default:
		return fmt.Errorf("unknown user command: %s", cmd)
	}
}

// handleAddUser handles the adduser command
func (h *UserHandler) handleAddUser(ctx context.Context, args *common.CommandArgs) (int, string, error) {
	data := userDataFromArgs(args)

	err := h.Validate(common.AddUser.String(), args)
	if err != nil {
		return 1, err.Error(), nil
	}

	log.Info().
		Str("username", data.Username).
		Uint64("uid", data.UID).
		Uint64("gid", data.GID).
		Str("home", data.HomeDirectory).
		Msg("Adding user")

	var exitCode int
	var output string

	// Platform-specific user addition.
	// UID/GID/HomeDirectory flags are omitted only when IsServiceAccount=true
	// AND the value is zero/empty, so the OS can auto-assign. For IAM User
	// payloads (IsServiceAccount=false), these fields are validated as
	// required upstream: if we ever reach this point with zero values, we
	// still pass whatever was provided rather than silently rewriting the
	// command, since defense-in-depth is cheap.
	omitUID := data.IsServiceAccount && data.UID == 0
	omitGID := data.IsServiceAccount && data.GID == 0
	omitHome := data.IsServiceAccount && data.HomeDirectory == ""

	switch utils.PlatformLike {
	case "debian":
		cmdArgs := []string{}
		if !omitHome {
			cmdArgs = append(cmdArgs, "--home", data.HomeDirectory)
		}
		cmdArgs = append(cmdArgs, "--shell", data.Shell)
		if !omitUID {
			cmdArgs = append(cmdArgs, "--uid", strconv.FormatUint(data.UID, 10))
		}
		if !omitGID {
			cmdArgs = append(cmdArgs, "--gid", strconv.FormatUint(data.GID, 10))
		}
		cmdArgs = append(cmdArgs, "--gecos", data.Comment, "--disabled-password", data.Username)
		exitCode, output, err = h.Executor.Run(ctx, "/usr/sbin/adduser", cmdArgs...)
		if exitCode != 0 {
			return exitCode, output, err
		}
	case "rhel":
		// Create primary group only when an explicit GID is requested.
		// Without GID (service-account path), useradd auto-creates a group
		// matching the username.
		if !omitGID {
			exitCode, output, err = h.Executor.Run(
				ctx,
				"/usr/sbin/groupadd",
				"--gid", strconv.FormatUint(data.GID, 10),
				data.Groupname,
			)
			// Ignore if group already exists
			if exitCode != 0 && !strings.Contains(output, "already exists") {
				return exitCode, output, err
			}
		}

		cmdArgs := []string{}
		if !omitHome {
			cmdArgs = append(cmdArgs, "--home-dir", data.HomeDirectory)
		}
		cmdArgs = append(cmdArgs, "--shell", data.Shell)
		if !omitUID {
			cmdArgs = append(cmdArgs, "--uid", strconv.FormatUint(data.UID, 10))
		}
		if !omitGID {
			cmdArgs = append(cmdArgs, "--gid", strconv.FormatUint(data.GID, 10))
		}
		cmdArgs = append(cmdArgs, "--comment", data.Comment, "--create-home", data.Username)
		exitCode, output, err = h.Executor.Run(ctx, "/usr/sbin/useradd", cmdArgs...)
		if exitCode != 0 {
			return exitCode, output, err
		}
	default:
		return 1, fmt.Sprintf("Platform '%s' not supported for user management", utils.PlatformLike), nil
	}

	// Set home directory permissions if specified.
	// Skip when HomeDirectory was omitted (OS default path), since the caller
	// didn't specify a target and we would otherwise chmod an empty path.
	// codeql[go/path-injection]: Intentional - Admin-specified home directory permission
	if data.HomeDirectory != "" && data.HomeDirectoryPermission != "" && data.HomeDirectoryPermission != "0755" {
		mode, err := strconv.ParseUint(data.HomeDirectoryPermission, 8, 32)
		if err == nil {
			_ = os.Chmod(data.HomeDirectory, os.FileMode(mode)) // lgtm[go/path-injection]
		}
	}

	// Service-account Groupname setup.
	// Runs BEFORE AddUserToGroups so the critical `Groupname` membership is
	// established even if the optional supplementary `Groups` list fails and
	// triggers the early return below.
	// Gated on `omitGID`: when GID is provided, the RHEL path already ran
	// `groupadd --gid <GID> <Groupname>` and `useradd --gid <GID>`, making the
	// user a member of Groupname as the primary group. Re-running groupadd/
	// usermod there would be redundant. When GID is omitted (the typical
	// service-account payload), useradd auto-creates a per-user primary group
	// and the user is NOT in `Groupname`, which would break later
	// `utils.Demote(..., ValidateGroup=true)` calls.
	if data.IsServiceAccount && omitGID && data.Groupname != "" {
		// Ensure the group exists (groupadd -f is a no-op if it already does).
		// Non-fatal: if this fails (missing binary, permissions, corrupt group
		// db), usermod below will also fail and later Demote errors become
		// hard to diagnose, so log the actual groupadd failure here.
		if code, out, err := h.Executor.Run(ctx, "/usr/sbin/groupadd", "-f", data.Groupname); code != 0 {
			log.Warn().
				Str("group", data.Groupname).
				Int("exitCode", code).
				Str("output", out).
				Err(err).
				Msg("Failed to ensure supplementary group exists (groupadd -f); usermod will likely fail")
		}
		// Add the user to the group as a supplementary member. Non-fatal: log
		// a warning so the root cause surfaces instead of silently breaking
		// later Demote calls.
		if code, out, err := h.Executor.Run(ctx, "/usr/sbin/usermod", "-aG", data.Groupname, data.Username); code != 0 {
			log.Warn().
				Str("user", data.Username).
				Str("group", data.Groupname).
				Int("exitCode", code).
				Str("output", out).
				Err(err).
				Msg("Failed to add service account to supplementary group")
		}
	}

	// Add user to additional groups if specified
	if len(data.Groups) > 0 && h.groupService != nil {
		if err := h.groupService.AddUserToGroups(ctx, data.Username, data.Groups); err != nil {
			log.Warn().Err(err).Msg("Failed to add user to additional groups")
			return 0, fmt.Sprintf("User '%s' created but failed to add to groups: %v", data.Username, err), nil
		}
	}

	log.Info().
		Str("username", data.Username).
		Int("exitCode", exitCode).
		Msg("User added successfully")

	return exitCode, fmt.Sprintf("User '%s' added successfully", data.Username), nil
}

// backupHomeDirectory backs up the user's home directory before deletion
func (h *UserHandler) backupHomeDirectory(username string) error {
	homeDir := fmt.Sprintf("/home/%s", username)
	timestamp := time.Now().UTC().Format(time.RFC3339)
	backupDir := fmt.Sprintf("/home/deleted_users/%s_%s", username, timestamp)

	// Create backup parent directory
	if err := os.MkdirAll("/home/deleted_users", 0700); err != nil {
		return fmt.Errorf("failed to create backup directory: %w", err)
	}

	// Check if home directory exists
	// codeql[go/path-injection]: Intentional - User home directory for backup
	if _, err := os.Stat(homeDir); err != nil { // lgtm[go/path-injection]
		return fmt.Errorf("%s not exist: %w", homeDir, err)
	}

	// Move home directory to backup location
	// codeql[go/path-injection]: Intentional - Backup destination path
	if err := os.Rename(homeDir, backupDir); err != nil { // lgtm[go/path-injection]
		return fmt.Errorf("failed to move home directory: %w", err)
	}

	// Change ownership to root
	if err := utils.ChownRecursive(backupDir, 0, 0); err != nil {
		return fmt.Errorf("failed to chown backup directory: %w", err)
	}

	log.Info().
		Str("username", username).
		Str("backupDir", backupDir).
		Msg("Home directory backed up")

	return nil
}

// handleDelUser handles the deluser command
func (h *UserHandler) handleDelUser(ctx context.Context, args *common.CommandArgs) (int, string, error) {
	// Extract and validate arguments
	data := DeleteUserData{
		Username:           args.Username,
		PurgeHomeDirectory: args.PurgeHomeDirectory,
	}

	err := h.Validate(common.DelUser.String(), args)
	if err != nil {
		return 1, err.Error(), nil
	}

	log.Info().
		Str("username", data.Username).
		Bool("purge", data.PurgeHomeDirectory).
		Msg("Deleting user")

	// Backup home directory if not purging
	if !data.PurgeHomeDirectory {
		if err := h.backupHomeDirectory(data.Username); err != nil {
			return 1, err.Error(), nil
		}
	}

	var exitCode int
	var output string
	cmdArgs := []string{}

	// Platform-specific user deletion
	switch utils.PlatformLike {
	case "debian":
		cmdArgs = append(cmdArgs, "/usr/sbin/deluser")
		if data.PurgeHomeDirectory {
			cmdArgs = append(cmdArgs, "--remove-home")
		}
		cmdArgs = append(cmdArgs, data.Username)
	case "rhel":
		cmdArgs = append(cmdArgs, "/usr/sbin/userdel")
		if data.PurgeHomeDirectory {
			cmdArgs = append(cmdArgs, "-r")
		}
		cmdArgs = append(cmdArgs, data.Username)
	default:
		return 1, fmt.Sprintf("Platform '%s' not supported for user management", utils.PlatformLike), nil
	}

	exitCode, output, err = h.Executor.Run(
		ctx,
		cmdArgs[0], cmdArgs[1:]...,
	)
	if exitCode != 0 {
		return exitCode, output, err
	}

	log.Info().
		Str("username", data.Username).
		Int("exitCode", exitCode).
		Msg("User deleted successfully")

	return exitCode, fmt.Sprintf("User '%s' deleted successfully", data.Username), nil
}

// handleModUser handles the moduser command
func (h *UserHandler) handleModUser(ctx context.Context, args *common.CommandArgs) (int, string, error) {
	// Extract and validate arguments
	data := ModUserData{
		Username:   args.Username,
		Groupnames: args.Groupnames,
		Comment:    args.Comment,
	}

	err := h.Validate(common.ModUser.String(), args)
	if err != nil {
		return 1, err.Error(), nil
	}

	log.Info().
		Str("username", data.Username).
		Strs("groups", data.Groupnames).
		Str("comment", data.Comment).
		Msg("Modifying user")

	// Build usermod arguments
	cmdArgs := []string{"/usr/sbin/usermod"}
	if data.Comment != "" {
		cmdArgs = append(cmdArgs, "--comment", data.Comment)
	}
	if len(data.Groupnames) > 0 {
		cmdArgs = append(cmdArgs, "-G", strings.Join(data.Groupnames, ","))
	}
	cmdArgs = append(cmdArgs, data.Username)

	// Execute usermod
	exitCode, output, err := h.Executor.Run(ctx, cmdArgs[0], cmdArgs[1:]...)
	if exitCode != 0 {
		return exitCode, output, err
	}

	log.Info().
		Str("username", data.Username).
		Int("exitCode", exitCode).
		Msg("User modified successfully")

	return exitCode, fmt.Sprintf("User '%s' modified successfully", data.Username), nil
}
