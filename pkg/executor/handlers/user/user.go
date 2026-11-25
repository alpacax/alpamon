package user

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/alpacax/alpamon/v2/pkg/executor/handlers/common"
	"github.com/alpacax/alpamon/v2/pkg/executor/services"
	"github.com/alpacax/alpamon/v2/pkg/utils"
	"github.com/rs/zerolog/log"
)

// UserHandler handles user management commands.
// Unlock starts nothing, including triggers. Rate-limited triggers are reported
// and left for the owner to start.
// The server must refuse Websh, exec and file access for locked accounts because Alpamon switches users without PAM.
type UserHandler struct {
	*common.BaseHandler
	groupService services.GroupService
	syncManager  common.SystemInfoManager
	// lookupUser / lookupGroup verify existence before creating (idempotency
	// gate), and supplementaryGroups reads current memberships for moduser.
	// They default to local-file implementations and are overridden in tests.
	// See pkg/executor/handlers/common/lookup.go.
	lookupUser          common.UserLookupFunc
	lookupGroup         common.GroupLookupFunc
	supplementaryGroups common.SupplementaryGroupsFunc
	accountLocker       accountLocker
	homeRoot            string
	scanHomeOwners      func(context.Context, string, string, string, bool) homeScanResult
	readAccountFile     func(string) ([]byte, error)
	chownHome           func(context.Context, int, string, int, int, int) (int, error)
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
				common.LockUser,
				common.UnlockUser,
			},
			cmdExecutor,
		),
		groupService:        groupService,
		syncManager:         syncManager,
		lookupUser:          common.DefaultUserLookup,
		lookupGroup:         common.DefaultGroupLookup,
		supplementaryGroups: common.DefaultSupplementaryGroups,
		homeRoot:            "/home",
		scanHomeOwners:      scanHomeOwners,
		readAccountFile:     os.ReadFile,
	}
	h.accountLocker = newAccountLocker(h)
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

	select {
	case accountLockGate <- struct{}{}:
		defer func() { <-accountLockGate }()
	case <-ctx.Done():
		return 1, "account_command_failed: " + ctx.Err().Error(), nil
	}

	var exitCode int
	var output string
	var err error

	switch cmd {
	case common.AddUser.String():
		exitCode, output, err = h.handleAddUser(ctx, args)
	case common.DelUser.String():
		exitCode, output, err = h.handleDelUser(ctx, args)
	case common.LockUser.String(), common.UnlockUser.String():
		exitCode, output, err = h.accountLocker.execute(ctx, cmd, args)
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
	case common.LockUser.String(), common.UnlockUser.String():
		if runtime.GOOS != "linux" {
			return fmt.Errorf("unsupported_platform: account locking requires Linux")
		}
		return validateLockUser(args)
	case common.AddUser.String():
		return h.ValidateStruct(userDataFromArgs(args))

	case common.DelUser.String():
		return h.ValidateStruct(deleteUserDataFromArgs(args))

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

	if err := h.ValidateStruct(data); err != nil {
		return 1, err.Error(), nil
	}

	// Check the same explicit path that the create command will use.
	if data.HomeDirectory != "" {
		data.HomeDirectory = filepath.Clean(data.HomeDirectory)
	}

	log.Info().
		Str("username", data.Username).
		Uint64("uid", data.UID).
		Uint64("gid", data.GID).
		Str("home", data.HomeDirectory).
		Msg("Adding user")

	uidRequested := data.UID != 0
	omitGIDFlag := data.IsServiceAccount && data.GID == 0
	homeOmitted := data.HomeDirectory == ""

	// Idempotency gate (M8): verify by lookup whether the user already exists
	// before attempting creation, so re-provisioning an already-present account
	// is a no-op instead of a hard adduser/useradd "already exists" failure
	// (the #344 root cause). The lookup is the PRIMARY decision; a create-time
	// secondary net (below) covers TOCTOU races and NSS-backed names invisible
	// to the CGO_ENABLED=0 pure-Go resolver.
	//
	// A same-name/different-uid account is real drift and is surfaced as a
	// failure, never masked. When the uid is omitted (service account), name presence alone marks the account as provisioned.
	existing, userExists, lookupErr := common.UserExists(h.lookupUser, data.Username)
	if lookupErr != nil {
		// We cannot confirm the current state; do not blind-create over a
		// possibly-shadowed entry. Fail loud so the drift is visible.
		return 1, fmt.Sprintf("unable to verify whether user %q exists: %v", data.Username, lookupErr), lookupErr
	}
	if userExists && uidRequested {
		existingUID, perr := strconv.ParseUint(existing.Uid, 10, 64)
		if perr != nil {
			return 1, fmt.Sprintf("user %q exists but its uid %q is not a valid number; refusing to modify an existing account", data.Username, existing.Uid), nil
		}
		if existingUID != data.UID {
			return 1, common.UserUIDConflictMessage(data.Username, existingUID, data.UID), nil
		}
	}

	if !userExists && !validHomeUsername(data.Username) {
		return 1, fmt.Sprintf("invalid username %q", data.Username), nil
	}

	if !userExists && (utils.PlatformLike == "debian" || utils.PlatformLike == "rhel") {
		root, err := h.defaultHomeRoot()
		if err != nil {
			return 1, err.Error(), nil
		}
		home := data.HomeDirectory
		if homeOmitted {
			home = filepath.Join(root, data.Username)
		}
		home = filepath.Clean(home)
		scan := h.homeOwners(ctx, home, root, !uidRequested)
		if scan.err != nil {
			return 1, scan.err.Error(), nil
		}
		if !uidRequested {
			data.UID, err = h.nextServiceUID(scan.owners)
			if err != nil {
				return 1, err.Error(), nil
			}
		}
		if err := checkHomeOwner(home, scan.target, data.UID); err != nil {
			return 1, err.Error(), nil
		}
		if path, found := scan.owners[data.UID]; found {
			return 1, fmt.Sprintf("system_home_conflict: %s is owned by requested uid %d; refusing to create the account", path, data.UID), nil
		}
		data.HomeDirectory = home
	}

	// Service-account primary-group bootstrap (load-bearing).
	//
	// When the payload omits a numeric GID, we want the user's primary
	// group to be `Groupname` (e.g. "alpacon") so that later
	// `utils.Demote(..., ValidateGroup=true)` succeeds. Setting it as a
	// post-fact supplementary membership via `usermod -aG` is fragile
	// on systems with USERGROUPS_ENAB=no / Debian USERGROUPS=no.
	//
	// Instead, ensure the named group exists up front, then pass it as
	// the primary group to adduser/useradd via `--ingroup` (Debian) or
	// `--gid <name>` (RHEL: useradd accepts a group name as well as a
	// numeric id). If `groupadd -f` fails here, fail loudly so the
	// caller does not see a "succeeded" provisioning that breaks at
	// runtime.
	// `omitGIDFlag` already implies `data.IsServiceAccount` per its definition.
	if omitGIDFlag && data.Groupname != "" {
		if code, out, gerr := h.Executor.Run(ctx, "/usr/sbin/groupadd", "-f", data.Groupname); code != 0 {
			log.Error().
				Str("group", data.Groupname).
				Int("exitCode", code).
				Str("output", out).
				Err(gerr).
				Msg("Failed to ensure service-account primary group exists")
			return code, fmt.Sprintf("Failed to ensure group %q for service account: %s", data.Groupname, out), gerr
		}
	}

	switch utils.PlatformLike {
	case "debian":
		if !userExists {
			cmdArgs := []string{"--home", data.HomeDirectory}
			cmdArgs = append(cmdArgs, "--shell", data.Shell)
			cmdArgs = append(cmdArgs, "--uid", strconv.FormatUint(data.UID, 10))
			switch {
			case omitGIDFlag && data.Groupname != "":
				// Service-account path: set primary group by name so the user
				// joins `Groupname` regardless of USERGROUPS settings.
				cmdArgs = append(cmdArgs, "--ingroup", data.Groupname)
			case !omitGIDFlag:
				cmdArgs = append(cmdArgs, "--gid", strconv.FormatUint(data.GID, 10))
			}
			cmdArgs = append(cmdArgs, "--gecos", data.Comment, "--disabled-password", data.Username)
			existed, code, out, cerr := h.runUserCreate(ctx, "/usr/sbin/adduser", cmdArgs, data, uidRequested)
			if code != 0 {
				return code, out, cerr
			}
			if existed {
				userExists = true
			}
		}
	case "rhel":
		// Ensure the primary group exists with the explicit GID for IAM User
		// payloads. Service-account payloads (omitGIDFlag=true) already ran
		// `groupadd -f` above and will use `--gid <Groupname>` below.
		//
		// This runs whether or not the user exists—it is an idempotent
		// "ensure", gated by the same lookup rule as standalone addgroup (A-3
		// consistency): a matching gid skips creation, a different gid surfaces
		// a conflict, and creation keeps a lookup-reverify secondary net.
		if !omitGIDFlag {
			needCreate, code, out, gerr := common.ClassifyGroupForCreate(h.lookupGroup, data.Groupname, data.GID)
			if code != 0 {
				return code, out, gerr
			}
			if needCreate {
				code, out, gerr = h.Executor.Run(
					ctx,
					"/usr/sbin/groupadd",
					"--gid", strconv.FormatUint(data.GID, 10),
					data.Groupname,
				)
				code, out, gerr = common.ReconcileGroupCreate(h.lookupGroup, data.Groupname, data.GID, code, out, gerr)
				if code != 0 {
					return code, out, gerr
				}
			}
		}

		if !userExists {
			cmdArgs := []string{"--home-dir", data.HomeDirectory}
			cmdArgs = append(cmdArgs, "--shell", data.Shell)
			cmdArgs = append(cmdArgs, "--uid", strconv.FormatUint(data.UID, 10))
			switch {
			case omitGIDFlag && data.Groupname != "":
				// Service-account path: useradd accepts a group name for --gid.
				cmdArgs = append(cmdArgs, "--gid", data.Groupname)
			case !omitGIDFlag:
				cmdArgs = append(cmdArgs, "--gid", strconv.FormatUint(data.GID, 10))
			}
			cmdArgs = append(cmdArgs, "--comment", data.Comment, "--create-home", data.Username)
			existed, code, out, cerr := h.runUserCreate(ctx, "/usr/sbin/useradd", cmdArgs, data, uidRequested)
			if code != 0 {
				return code, out, cerr
			}
			if existed {
				userExists = true
			}
		}
	default:
		return 1, fmt.Sprintf("Platform '%s' not supported for user management", utils.PlatformLike), nil
	}

	// Set home directory permissions if specified.
	//
	// Only for a freshly-created account (!userExists). We do not chmod an
	// existing user's home: it matches the "don't modify an existing account"
	// contract (we also don't usermod -g), and it avoids a root chmod that would
	// follow a symlink an existing—possibly hostile—local user could plant at
	// their home path.
	//
	// Apply an explicit mode only to a caller-supplied home path.
	// codeql[go/path-injection]: Intentional - Admin-specified home directory permission
	if !userExists && !homeOmitted && data.HomeDirectoryPermission != "" && data.HomeDirectoryPermission != "0755" {
		mode, err := strconv.ParseUint(data.HomeDirectoryPermission, 8, 32)
		if err == nil {
			_ = os.Chmod(data.HomeDirectory, os.FileMode(mode)) // lgtm[go/path-injection]
		}
	}

	// Add user to additional groups if specified
	if !userExists && len(data.Groups) > 0 && h.groupService != nil {
		if err := h.groupService.AddUserToGroups(ctx, data.Username, data.Groups); err != nil {
			log.Warn().Err(err).Msg("Failed to add user to additional groups")
			return 0, fmt.Sprintf("User '%s' created (uid: %d) but failed to add to groups: %v", data.Username, data.UID, err), nil
		}
	}

	log.Info().
		Str("username", data.Username).
		Bool("alreadyExisted", userExists).
		Msg("User provisioning completed")

	if userExists {
		return 0, fmt.Sprintf("User '%s' already exists", data.Username), nil
	}
	return 0, fmt.Sprintf("User '%s' added successfully (uid: %d)", data.Username, data.UID), nil
}

// runUserCreate runs the platform create command (adduser/useradd) and applies
// the create-time reconcile net, so both platform branches share one copy of
// the "create then reconcile" contract. It returns:
//   - existed=true when a non-zero create was reconciled to idempotent success
//     (the account already existed: a raced or NSS/LDAP-backed name); the caller
//     should treat the user as pre-existing.
//   - code!=0 when the create genuinely failed—the caller must return
//     (code, out, err) unchanged.
//
// On success (code==0) the caller continues to the idempotent ensure steps.
func (h *UserHandler) runUserCreate(ctx context.Context, tool string, cmdArgs []string, data UserData, uidRequested bool) (existed bool, code int, out string, err error) {
	createCode, createOut, createErr := h.Executor.Run(ctx, tool, cmdArgs...)
	// Secondary net: a raced or LDAP/SSSD-backed account (invisible to the
	// pure-Go lookup) may cause a non-zero "already exists". Re-verify and treat
	// a matching account as idempotent success.
	code, out, err = common.ReconcileUserCreate(h.lookupUser, data.Username, data.UID, uidRequested, createCode, createOut, createErr)
	if code != 0 {
		return false, code, out, err
	}
	return createCode != 0, 0, out, err
}

type archiveSkip struct {
	detail string
}

func (s *archiveSkip) Error() string { return "archive_skipped: " + s.detail }

func (h *UserHandler) handleDelUser(ctx context.Context, args *common.CommandArgs) (exitCode int, output string, err error) {
	data := deleteUserDataFromArgs(args)
	if err := h.ValidateStruct(data); err != nil {
		return 1, err.Error(), nil
	}
	if !validHomeUsername(data.Username) || strings.HasPrefix(data.Username, "-") {
		return 1, fmt.Sprintf("invalid username %q", data.Username), nil
	}

	if utils.PlatformLike != "debian" && utils.PlatformLike != "rhel" {
		return 1, fmt.Sprintf("Platform '%s' not supported for user management", utils.PlatformLike), nil
	}

	log.Info().Str("username", data.Username).Str("home", data.Home).Msg("Deleting user")

	account, exists, lookupErr := common.UserExists(h.lookupUser, data.Username)
	if lookupErr != nil {
		if data.Home == "archive" {
			return 1, fmt.Sprintf("archive_refused: unable to look up user %q: %v", data.Username, lookupErr), nil
		}
		return 1, fmt.Sprintf("unable to look up user %q: %v", data.Username, lookupErr), lookupErr
	}
	if !exists {
		if err := h.accountLocker.clearPendingArchive(data.Username); err != nil {
			defer func() { output += "\npending_record_cleanup_failed: " + err.Error() }()
		}
		if err := h.accountLocker.forget(data.Username); err != nil {
			log.Warn().Err(err).Str("username", data.Username).Msg("Failed to forget deleted user lock state")
			defer func() { output += "\nlock_cleanup_failed: " + err.Error() }()
		}
		return h.Executor.Run(ctx, "/usr/sbin/userdel", data.Username)
	}

	result := "home directory kept at " + account.HomeDir
	archived := false
	var skipped *archiveSkip
	if data.Home == "archive" {
		destination, archiveErr := h.accountLocker.archiveHome(ctx, account, data)
		switch {
		case errors.As(archiveErr, &skipped):
			result = skipped.Error()
		case archiveErr != nil:
			return 1, archiveErr.Error(), nil
		case destination == "":
			result = fmt.Sprintf("home directory %s not found; nothing archived", filepath.Clean(account.HomeDir))
		default:
			data.ArchiveTo = destination
			archived = true
			result = "home directory archived to " + destination
		}
		if data.LegacyPurge && skipped == nil {
			result += " (legacy purge_home=true treated as archive)"
		}
	}

	// Debian's deluser can remove files based on local configuration alone.
	exitCode, output, err = h.Executor.Run(ctx, "/usr/sbin/userdel", data.Username)
	if exitCode != 0 || err != nil {
		if archived {
			return 1, archivedDeleteFailure(data.ArchiveTo, fmt.Errorf("userdel exited %d: %s (%v)", exitCode, output, err)).Error(), nil
		}
		return exitCode, output, err
	}
	if archived {
		if cleanupErr := h.accountLocker.clearPendingArchive(data.Username); cleanupErr != nil {
			defer func() { output += "\npending_record_cleanup_failed: " + cleanupErr.Error() }()
		}
	}
	if err := h.accountLocker.forget(data.Username); err != nil {
		log.Warn().Err(err).Str("username", data.Username).Msg("Failed to forget deleted user lock state")
		if skipped != nil {
			result += "\nlock_cleanup_failed: " + err.Error()
		}
	}
	if skipped != nil {
		return 0, result, nil
	}
	return 0, fmt.Sprintf("User '%s' deleted; %s", data.Username, result), nil
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
	if args.ManagedGroupnames != nil {
		// Reconcile mode: usermod -G replaces the whole supplementary list,
		// so keep every current group Alpacon does not manage.
		current, err := h.supplementaryGroups(data.Username)
		if err != nil {
			return 1, fmt.Sprintf("failed to read current groups of %s: %v", data.Username, err), nil
		}
		groups := reconcileGroupnames(current, args.ManagedGroupnames, data.Groupnames)
		log.Info().
			Str("username", data.Username).
			Strs("current", current).
			Strs("managed", args.ManagedGroupnames).
			Strs("result", groups).
			Msg("Reconciled supplementary groups")
		cmdArgs = append(cmdArgs, "-G", strings.Join(groups, ","))
	} else if len(data.Groupnames) > 0 {
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

// reconcileGroupnames returns (current - managed) + requested, keeping current
// order first and dropping duplicates.
func reconcileGroupnames(current, managed, requested []string) []string {
	managedSet := make(map[string]struct{}, len(managed))
	for _, name := range managed {
		managedSet[name] = struct{}{}
	}
	seen := make(map[string]struct{}, len(current)+len(requested))
	result := make([]string, 0, len(current)+len(requested))
	add := func(name string) {
		if _, ok := seen[name]; ok {
			return
		}
		seen[name] = struct{}{}
		result = append(result, name)
	}
	for _, name := range current {
		if _, ok := managedSet[name]; !ok {
			add(name)
		}
	}
	for _, name := range requested {
		add(name)
	}
	return result
}
