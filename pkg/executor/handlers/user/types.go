package user

import "github.com/alpacax/alpamon/pkg/executor/handlers/common"

// UserData contains data for user operations.
//
// IsServiceAccount discriminates IAM User provisioning from Application
// service-account provisioning:
//   - IsServiceAccount=false (default, IAM User): UID/GID/HomeDirectory are
//     required. alpacon-server centrally assigns these for cross-server
//     consistency. Missing values indicate a server-side bug and must fail
//     validation rather than silently fall back to OS auto-assignment.
//   - IsServiceAccount=true (Application): UID/GID/HomeDirectory are optional.
//     When omitted, the numeric --uid / --gid / --home flag is skipped:
//     UID and HomeDirectory fall back to OS defaults; GID is replaced with
//     `--ingroup <Groupname>` (Debian) or `--gid <Groupname>` (RHEL) so the
//     primary group is set by name. Cross-server consistency is not required
//     because alpacon-server matches service accounts by username.
type UserData struct {
	Username                string   `validate:"required"`
	UID                     uint64   `validate:"required_unless=IsServiceAccount true"`
	GID                     uint64   `validate:"required_unless=IsServiceAccount true"`
	Comment                 string   `validate:"required"`
	HomeDirectory           string   `validate:"required_unless=IsServiceAccount true"`
	HomeDirectoryPermission string   `validate:"omitempty"`
	Shell                   string   `validate:"required"`
	Groupname               string   `validate:"required"`
	Groups                  []uint64 `validate:"omitempty"`
	IsServiceAccount        bool
}

// userDataFromArgs builds a UserData from CommandArgs, defaulting empty
// HomeDirectoryPermission to "0755". Shell is intentionally NOT defaulted
// here (see comment below). Shared by Validate and handleAddUser so both
// paths see identical field population.
func userDataFromArgs(args *common.CommandArgs) UserData {
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
		IsServiceAccount:        args.IsServiceAccount,
	}
	if data.HomeDirectoryPermission == "" {
		data.HomeDirectoryPermission = "0755"
	}
	// Shell is intentionally NOT defaulted: defaulting it before
	// ValidateStruct would mask an empty `shell` payload (the
	// `validate:"required"` tag could never fire) and silently
	// give a service account an interactive `/bin/bash`. alpacon-server
	// already always sends Shell explicitly (e.g. `/usr/sbin/nologin`
	// for Application service accounts, `user.shell` for IAM Users),
	// so the validator catching missing `shell` is the desired contract.
	return data
}

// DeleteUserData contains data for user deletion
type DeleteUserData struct {
	Username           string `validate:"required"`
	PurgeHomeDirectory bool   `validate:"omitempty"`
}

// ModUserData contains data for modifying user
type ModUserData struct {
	Username   string   `validate:"required"`
	Groupnames []string `validate:"required"`
	Comment    string   `validate:"required"`
}
