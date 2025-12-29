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
		data := UserData{
			Username:                args.Username,
			UID:                     args.UID,
			GID:                     args.GID,
			Comment:                 args.Comment,
			HomeDirectory:           args.HomeDirectory,
			HomeDirectoryPermission: args.HomeDirectoryPermission,
			Shell:                   args.Shell,
			Groupname:               args.Groupname,
			Groups:                  args.Groups,
		}
		if data.HomeDirectoryPermission == "" {
			data.HomeDirectoryPermission = "0755"
		}
		if data.Shell == "" {
			data.Shell = "/bin/bash"
		}
		return h.ValidateStruct(data)

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
	// Extract and validate arguments
	data := UserData{
		Username:                args.Username,
		UID:                     args.UID,
		GID:                     args.GID,
		Comment:                 args.Comment,
		HomeDirectory:           args.HomeDirectory,
		HomeDirectoryPermission: args.HomeDirectoryPermission,
		Shell:                   args.Shell,
		Groupname:               args.Groupname,
		Groups:                  args.Groups,
	}
	if data.HomeDirectoryPermission == "" {
		data.HomeDirectoryPermission = "0755"
	}
	if data.Shell == "" {
		data.Shell = "/bin/bash"
	}

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

	// Platform-specific user addition
	if utils.PlatformLike == "debian" {
		exitCode, output, err = h.Executor.Run(
			ctx,
			"/usr/sbin/adduser",
			"--home", data.HomeDirectory,
			"--shell", data.Shell,
			"--uid", strconv.FormatUint(data.UID, 10),
			"--gid", strconv.FormatUint(data.GID, 10),
			"--gecos", data.Comment,
			"--disabled-password",
			data.Username,
		)
		if exitCode != 0 {
			return exitCode, output, err
		}
	} else if utils.PlatformLike == "rhel" {
		// Create primary group first if needed
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

		// Create user
		exitCode, output, err = h.Executor.Run(
			ctx,
			"/usr/sbin/useradd",
			"--home-dir", data.HomeDirectory,
			"--shell", data.Shell,
			"--uid", strconv.FormatUint(data.UID, 10),
			"--gid", strconv.FormatUint(data.GID, 10),
			"--comment", data.Comment,
			"--create-home",
			data.Username,
		)
		if exitCode != 0 {
			return exitCode, output, err
		}
	} else {
		return 1, fmt.Sprintf("Platform '%s' not supported for user management", utils.PlatformLike), nil
	}

	// Set home directory permissions if specified
	// codeql[go/path-injection]: Intentional - Admin-specified home directory permission
	if data.HomeDirectoryPermission != "" && data.HomeDirectoryPermission != "0755" {
		mode, err := strconv.ParseUint(data.HomeDirectoryPermission, 8, 32)
		if err == nil {
			_ = os.Chmod(data.HomeDirectory, os.FileMode(mode))
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
	if _, err := os.Stat(homeDir); err != nil {
		return fmt.Errorf("%s not exist: %w", homeDir, err)
	}

	// Move home directory to backup location
	// codeql[go/path-injection]: Intentional - Backup destination path
	if err := os.Rename(homeDir, backupDir); err != nil {
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
	if utils.PlatformLike == "debian" {
		cmdArgs = append(cmdArgs, "/usr/sbin/deluser")
		if data.PurgeHomeDirectory {
			cmdArgs = append(cmdArgs, "--remove-home")
		}
		cmdArgs = append(cmdArgs, data.Username)
	} else if utils.PlatformLike == "rhel" {
		cmdArgs = append(cmdArgs, "/usr/sbin/userdel")
		if data.PurgeHomeDirectory {
			cmdArgs = append(cmdArgs, "-r")
		}
		cmdArgs = append(cmdArgs, data.Username)
	} else {
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
