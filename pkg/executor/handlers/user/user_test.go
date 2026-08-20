//go:build !windows

// User management is unsupported on Windows (see pkg/executor/factory_windows.go:
// UserHandler is not registered there). The assertions in this file bake in
// Unix shadow/passwd semantics and hardcoded /usr/sbin/{adduser,deluser,usermod}
// paths, so they are Unix-only by construction. Tracked in alpamon issue #284
// under "excluded test packages".

package user

import (
	"context"
	"errors"
	"fmt"
	"os/user"
	"slices"
	"strings"
	"testing"

	"github.com/alpacax/alpamon/v2/pkg/executor/handlers/common"
	"github.com/alpacax/alpamon/v2/pkg/utils"
	"github.com/go-playground/validator/v10"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// validationFields names the struct fields a ValidateStruct error flags, so a
// table row can pin exactly which fields failed instead of accepting any error.
func validationFields(t *testing.T, err error) []string {
	t.Helper()
	var verrs validator.ValidationErrors
	require.ErrorAs(t, err, &verrs)
	fields := make([]string, 0, len(verrs))
	for _, verr := range verrs {
		fields = append(fields, verr.Field())
	}
	return fields
}

// invokedAt returns the execution order of the first command that ran as
// program with exactly args, or -1 if none did. The index is what lets a test
// assert that one command preceded another; common.Invoked answers the plain
// did-it-run question.
func invokedAt(mock *common.MockCommandExecutor, program string, args ...string) int {
	for i, c := range mock.GetExecutedCommands() {
		if c.Name == program && slices.Equal(c.Args, args) {
			return i
		}
	}
	return -1
}

// MockGroupService implements services.GroupService for testing
type MockGroupService struct {
	AddUserToGroupsCalled bool
	AddUserToGroupsError  error
}

func (m *MockGroupService) AddUserToGroups(ctx context.Context, username string, gids []uint64) error {
	m.AddUserToGroupsCalled = true
	return m.AddUserToGroupsError
}

// newTestUserHandler builds a UserHandler whose user/group lookups report
// absent by default (via the shared fakes in common/testing.go), so the create
// path runs deterministically and hermetically. Individual tests override
// h.lookupUser / h.lookupGroup to exercise the exists/conflict matrix.
func newTestUserHandler(exec common.CommandExecutor, gs *MockGroupService) *UserHandler {
	h := NewUserHandler(exec, gs, nil)
	h.lookupUser = common.AbsentUserLookup
	h.lookupGroup = common.AbsentGroupLookup
	return h
}

func TestUserHandler_Execute(t *testing.T) {
	tests := []struct {
		name         string
		cmd          string
		args         *common.CommandArgs
		setupMock    func(*common.MockCommandExecutor)
		groupService *MockGroupService
		wantCode     int
		wantErrMsg   string
		// wantOutputPart pins the diagnostic a failing row hands the
		// operator, for the paths that report through output, not err.
		wantOutputPart string
	}{
		{
			name: "adduser success debian",
			cmd:  "adduser",
			args: &common.CommandArgs{
				Username:      "testuser",
				UID:           1001,
				GID:           1001,
				Comment:       "Test User",
				HomeDirectory: "/home/testuser",
				Shell:         "/bin/bash",
				Groupname:     "testgroup",
				// No additional Groups: the group-add path is covered by
				// TestUserHandler_AddUserWithGroups, which pins its output.
			},
			setupMock: func(mock *common.MockCommandExecutor) {
				mock.SetResult(fmt.Sprintf("/usr/sbin/adduser --home /home/testuser --shell /bin/bash --uid %d --gid %d --gecos Test User --disabled-password testuser", 1001, 1001), 0, "User created", nil)
			},
			groupService: &MockGroupService{},
			wantCode:     0,
		},
		{
			name: "deluser success",
			cmd:  "deluser",
			args: &common.CommandArgs{
				Username:           "testuser",
				PurgeHomeDirectory: true,
			},
			setupMock: func(mock *common.MockCommandExecutor) {
				mock.SetResult("/usr/sbin/deluser --remove-home testuser", 0, "User deleted", nil)
			},
			groupService: &MockGroupService{},
			wantCode:     0,
		},
		{
			name: "moduser success",
			cmd:  "moduser",
			args: &common.CommandArgs{
				Username:   "testuser",
				Groupnames: []string{"sudo", "docker"},
				Comment:    "Updated comment",
			},
			setupMock: func(mock *common.MockCommandExecutor) {
				mock.SetResult("/usr/sbin/usermod -c Updated comment testuser", 0, "User comment updated", nil)
				mock.SetResult("/usr/sbin/usermod -G sudo,docker testuser", 0, "User groups updated", nil)
			},
			groupService: &MockGroupService{},
			wantCode:     0,
		},
		{
			name:         "unknown command",
			cmd:          "unknownuser",
			args:         &common.CommandArgs{},
			groupService: &MockGroupService{},
			wantCode:     1,
			wantErrMsg:   "unknown user command: unknownuser",
		},
		{
			name: "adduser missing username",
			cmd:  "adduser",
			args: &common.CommandArgs{
				UID: 1001,
				GID: 1001,
			},
			groupService:   &MockGroupService{},
			wantCode:       1,
			wantOutputPart: "Username",
		},
		{
			name: "adduser failure",
			cmd:  "adduser",
			args: &common.CommandArgs{
				Username:      "testuser",
				UID:           1001,
				GID:           1001,
				Comment:       "Test User",
				HomeDirectory: "/home/testuser",
				Shell:         "/bin/bash",
				Groupname:     "testgroup",
			},
			setupMock: func(mock *common.MockCommandExecutor) {
				mock.SetResult(fmt.Sprintf("/usr/sbin/adduser --home /home/testuser --shell /bin/bash --uid %d --gid %d --gecos Test User --disabled-password testuser", 1001, 1001), 1, "User add failed", errors.New("user add error"))
			},
			groupService: &MockGroupService{},
			wantCode:     1,
			wantErrMsg:   "user add error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set platform like to debian for the test
			originalPlatformLike := utils.PlatformLike
			utils.SetPlatformLike("debian")
			t.Cleanup(func() {
				utils.SetPlatformLike(originalPlatformLike)
			})

			mock := common.NewMockCommandExecutor(t)
			if tt.setupMock != nil {
				tt.setupMock(mock)
			}

			handler := newTestUserHandler(mock, tt.groupService)
			ctx := context.Background()

			exitCode, output, err := handler.Execute(ctx, tt.cmd, tt.args)

			if tt.wantErrMsg != "" {
				assert.EqualError(t, err, tt.wantErrMsg)
			} else {
				assert.NoError(t, err)
			}
			assert.Equal(t, tt.wantCode, exitCode)
			if tt.wantOutputPart != "" {
				assert.Contains(t, output, tt.wantOutputPart)
			}
			if exitCode == 0 && tt.wantErrMsg == "" {
				assert.NotEmpty(t, output, "a successful command must carry output")
			}
		})
	}
}

// TestUserHandler_AddUser_UidLess verifies that Application service account
// provisioning (no uid/gid/home_directory) results in adduser/useradd commands
// without the corresponding flags, letting the OS auto-assign.
func TestUserHandler_AddUser_UidLess(t *testing.T) {
	baseArgs := &common.CommandArgs{
		Username:         "gitlab-runner",
		Comment:          "GitLab Runner,,,,(alpacon-app)abc",
		Shell:            "/usr/sbin/nologin",
		Groupname:        "alpacon",
		IsServiceAccount: true,
		// UID, GID, HomeDirectory intentionally omitted: OS auto-assigns
	}

	tests := []struct {
		name        string
		platform    string
		wantProgram string
		wantFlags   []string // flags that must be present on wantProgram
		forbidFlags []string // flags that must NOT be present on wantProgram
	}{
		{
			name:        "debian uid-less adduser",
			platform:    "debian",
			wantProgram: "/usr/sbin/adduser",
			wantFlags:   []string{"--shell", "/usr/sbin/nologin", "--gecos", "--disabled-password", "gitlab-runner"},
			forbidFlags: []string{"--uid", "--gid", "--home"},
		},
		{
			name:        "rhel uid-less useradd",
			platform:    "rhel",
			wantProgram: "/usr/sbin/useradd",
			wantFlags:   []string{"--shell", "/usr/sbin/nologin", "--comment", "--create-home", "gitlab-runner"},
			// `--gid` is allowed on RHEL because the service-account path
			// now passes `--gid alpacon` (by name) to set the primary
			// group. The "no numeric gid leak" invariant is enforced by
			// the explicit `--gid alpacon` check below.
			forbidFlags: []string{"--uid", "--home-dir"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			originalPlatformLike := utils.PlatformLike
			utils.SetPlatformLike(tt.platform)
			t.Cleanup(func() {
				utils.SetPlatformLike(originalPlatformLike)
			})

			mock := common.NewMockCommandExecutor(t)
			handler := newTestUserHandler(mock, &MockGroupService{})

			exitCode, _, err := handler.Execute(context.Background(), "adduser", baseArgs)
			require.NoError(t, err)
			require.Equal(t, 0, exitCode)

			executed := mock.GetExecutedCommands()
			var target *common.ExecutedCommand
			var sawGidGroupadd bool
			useraddIndex := -1
			for i := range executed {
				c := executed[i]
				if c.Name == tt.wantProgram {
					target = &executed[i]
					useraddIndex = i
				}
				if c.Name == "/usr/sbin/groupadd" && strings.Contains(strings.Join(c.Args, " "), "--gid") {
					sawGidGroupadd = true
				}
			}
			groupaddDashFIndex := invokedAt(mock, "/usr/sbin/groupadd", "-f", "alpacon")

			require.NotNil(t, target, "%s must be invoked, got: %+v", tt.wantProgram, executed)
			joined := strings.Join(target.Args, " ")
			for _, want := range tt.wantFlags {
				assert.Contains(t, joined, want, "flag %q must be present", want)
			}
			for _, forbid := range tt.forbidFlags {
				assert.NotContains(t, joined, forbid, "args: %s", joined)
			}

			// Service account must NOT use the gid-based groupadd path
			// (that path is for IAM User only). It MUST run `groupadd -f
			// alpacon` BEFORE adduser/useradd so the named group exists,
			// and adduser/useradd MUST set the primary group by name
			// (--ingroup on Debian, --gid <name> on RHEL). Post-fact
			// `usermod -aG` is no longer used.
			assert.False(t, sawGidGroupadd, "the service-account path must not call groupadd with --gid")
			assert.NotEqual(t, -1, groupaddDashFIndex, "`groupadd -f alpacon` must ensure the named primary group exists")
			if groupaddDashFIndex >= 0 && useraddIndex >= 0 {
				assert.Less(t, groupaddDashFIndex, useraddIndex, "`groupadd -f` must run before %s", tt.wantProgram)
			}
			assert.False(t, mock.Invoked("/usr/sbin/usermod"), "post-fact `usermod` must not run; the primary group is set during adduser/useradd")

			// Verify the primary-group-by-name flag is on the create command itself.
			switch tt.platform {
			case "debian":
				assert.Contains(t, joined, "--ingroup alpacon", "adduser must set the primary group by name")
			case "rhel":
				assert.Contains(t, joined, "--gid alpacon", "useradd must set the primary group by name")
			}
		})
	}
}

// TestUserHandler_AddUser_ServiceAccountWithExplicitUID verifies that when a
// service-account payload sets the IsServiceAccount flag AND provides numeric
// UID/GID/HomeDirectory, the omit-* logic correctly honors the explicit
// values. Locks in the contract that `IsServiceAccount` alone does not strip
// flags; the value must also be zero/empty.
func TestUserHandler_AddUser_ServiceAccountWithExplicitUID(t *testing.T) {
	originalPlatformLike := utils.PlatformLike
	utils.SetPlatformLike("rhel")
	t.Cleanup(func() {
		utils.SetPlatformLike(originalPlatformLike)
	})

	mock := common.NewMockCommandExecutor(t)
	handler := newTestUserHandler(mock, &MockGroupService{})

	args := &common.CommandArgs{
		Username:         "explicit-svc",
		UID:              7000,
		GID:              7000,
		Comment:          "Explicit service account,,,,(alpacon-app)xyz",
		HomeDirectory:    "/var/lib/explicit-svc",
		Shell:            "/usr/sbin/nologin",
		Groupname:        "alpacon",
		IsServiceAccount: true,
	}

	exitCode, _, err := handler.Execute(context.Background(), "adduser", args)
	require.NoError(t, err)
	require.Equal(t, 0, exitCode)

	executed := mock.GetExecutedCommands()
	var useradd *common.ExecutedCommand
	var sawNamedGidUseradd bool
	for i, c := range executed {
		if c.Name == "/usr/sbin/useradd" {
			useradd = &executed[i]
			joined := strings.Join(c.Args, " ")
			if strings.Contains(joined, "--gid alpacon") {
				sawNamedGidUseradd = true
			}
		}
	}
	require.NotNil(t, useradd, "useradd must be invoked, got: %+v", executed)
	joined := strings.Join(useradd.Args, " ")
	for _, want := range []string{"--uid", "7000", "--gid", "7000", "--home-dir", "/var/lib/explicit-svc"} {
		assert.Contains(t, joined, want, "an explicit value must be honored on useradd")
	}
	assert.False(t, sawNamedGidUseradd, "an explicit non-zero GID must not take the by-name `--gid alpacon` path")
}

// TestUserHandler_AddUser_ServiceAccountGroupaddFails verifies that a
// failing `groupadd -f` on the service-account path is load-bearing:
// handleAddUser must return a non-zero exit code so alpacon-server sees
// the failure rather than a "succeeded" provisioning that breaks at
// `utils.Demote(..., ValidateGroup=true)` runtime.
func TestUserHandler_AddUser_ServiceAccountGroupaddFails(t *testing.T) {
	originalPlatformLike := utils.PlatformLike
	utils.SetPlatformLike("rhel")
	t.Cleanup(func() {
		utils.SetPlatformLike(originalPlatformLike)
	})

	mock := common.NewMockCommandExecutor(t)
	mock.SetResult("/usr/sbin/groupadd -f alpacon", 4, "groupadd: cannot lock /etc/group; try again later", errors.New("groupadd failed"))

	handler := newTestUserHandler(mock, &MockGroupService{})

	args := &common.CommandArgs{
		Username:         "gitlab-runner",
		Comment:          "GitLab Runner,,,,(alpacon-app)abc",
		Shell:            "/usr/sbin/nologin",
		Groupname:        "alpacon",
		IsServiceAccount: true,
	}

	exitCode, output, _ := handler.Execute(context.Background(), "adduser", args)
	require.NotEqual(t, 0, exitCode, "a failing groupadd on the service-account path must surface, output: %q", output)

	// useradd must not be reached if the primary group cannot be ensured.
	assert.False(t, mock.Invoked("/usr/sbin/useradd"),
		"useradd must not run when `groupadd -f` failed; got %+v", mock.GetExecutedCommands())
}

// TestUserHandler_AddUser_RhelWithUID verifies the existing IAM User path
// (uid/gid present) still runs groupadd and passes flags on RHEL.
func TestUserHandler_AddUser_RhelWithUID(t *testing.T) {
	originalPlatformLike := utils.PlatformLike
	utils.SetPlatformLike("rhel")
	t.Cleanup(func() {
		utils.SetPlatformLike(originalPlatformLike)
	})

	mock := common.NewMockCommandExecutor(t)
	handler := newTestUserHandler(mock, &MockGroupService{})

	args := &common.CommandArgs{
		Username:      "john",
		UID:           5001,
		GID:           5001,
		Comment:       "John,,,,(alpacon)uuid",
		HomeDirectory: "/home/john",
		Shell:         "/bin/bash",
		Groupname:     "alpacon",
	}

	exitCode, _, err := handler.Execute(context.Background(), "adduser", args)
	require.NoError(t, err)
	require.Equal(t, 0, exitCode)

	executed := mock.GetExecutedCommands()
	var sawGroupadd, sawUseradd bool
	for _, c := range executed {
		if c.Name == "/usr/sbin/groupadd" {
			sawGroupadd = true
			joined := strings.Join(c.Args, " ")
			assert.Contains(t, joined, "--gid 5001")
			assert.Contains(t, joined, "alpacon")
		}
		if c.Name == "/usr/sbin/useradd" {
			sawUseradd = true
			joined := strings.Join(c.Args, " ")
			for _, want := range []string{"--uid", "5001", "--gid", "--home-dir", "/home/john", "--shell", "/bin/bash", "--create-home", "john"} {
				assert.Contains(t, joined, want, "useradd is missing a flag")
			}
		}
	}
	assert.True(t, sawGroupadd, "groupadd must be invoked")
	assert.True(t, sawUseradd, "useradd must be invoked")
}

func TestUserHandler_Validate(t *testing.T) {
	handler := newTestUserHandler(common.NewMockCommandExecutor(t), &MockGroupService{})

	tests := []struct {
		name string
		cmd  string
		args *common.CommandArgs
		// wantErrMsg pins a non-validator error to its exact message;
		// wantErrFields pins a validator error to the exact set of fields it
		// must flag. Both empty means the args must validate.
		wantErrMsg    string
		wantErrFields []string
	}{
		{
			name: "adduser valid",
			cmd:  "adduser",
			args: &common.CommandArgs{
				Username:      "testuser",
				UID:           1001,
				GID:           1001,
				Comment:       "Test User",
				HomeDirectory: "/home/testuser",
				Shell:         "/bin/bash",
				Groupname:     "testgroup",
			},
		},
		{
			name: "adduser missing required fields",
			cmd:  "adduser",
			args: &common.CommandArgs{
				Username: "testuser",
				// IsServiceAccount=false (default), so UID/GID/HomeDirectory
				// are required_unless and also missing. Comment/Groupname are
				// required unconditionally. Shell carries `validate:"required"`
				// and is deliberately not defaulted (types.go:52), so it fails too.
			},
			wantErrFields: []string{"UID", "GID", "Comment", "HomeDirectory", "Shell", "Groupname"},
		},
		{
			name: "adduser uid-less service account valid",
			cmd:  "adduser",
			args: &common.CommandArgs{
				Username:         "gitlab-runner",
				Comment:          "GitLab Runner,,,,(alpacon-app)abc",
				Shell:            "/usr/sbin/nologin",
				Groupname:        "alpacon",
				IsServiceAccount: true,
				// UID/GID/HomeDirectory intentionally omitted (OS auto-assign)
			},
		},
		{
			name: "adduser IAM User path must still require uid, gid and home",
			cmd:  "adduser",
			args: &common.CommandArgs{
				Username:  "john",
				Comment:   "John,,,,(alpacon)uuid",
				Shell:     "/bin/bash",
				Groupname: "alpacon",
				// IsServiceAccount=false (default)
				// UID/GID/HomeDirectory missing: must fail
			},
			wantErrFields: []string{"UID", "GID", "HomeDirectory"},
		},
		{
			name: "adduser IAM User with uid=0 must fail (cannot silently auto-assign)",
			cmd:  "adduser",
			args: &common.CommandArgs{
				Username:      "john",
				UID:           0, // bug: alpacon-server sent zero
				GID:           5001,
				Comment:       "John,,,,(alpacon)uuid",
				HomeDirectory: "/home/john",
				Shell:         "/bin/bash",
				Groupname:     "alpacon",
				// IsServiceAccount=false: uid=0 must be rejected
			},
			wantErrFields: []string{"UID"},
		},
		{
			name: "deluser valid",
			cmd:  "deluser",
			args: &common.CommandArgs{
				Username: "testuser",
			},
		},
		{
			name: "moduser valid",
			cmd:  "moduser",
			args: &common.CommandArgs{
				Username:   "testuser",
				Groupnames: []string{"sudo"},
				Comment:    "Updated",
			},
		},
		{
			name:       "unknown command",
			cmd:        "unknown",
			args:       &common.CommandArgs{},
			wantErrMsg: "unknown user command: unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := handler.Validate(tt.cmd, tt.args)
			switch {
			case tt.wantErrMsg != "":
				assert.EqualError(t, err, tt.wantErrMsg)
			case len(tt.wantErrFields) > 0:
				assert.ElementsMatch(t, tt.wantErrFields, validationFields(t, err))
			default:
				assert.NoError(t, err)
			}
		})
	}
}

func TestUserHandler_AddUserWithGroups(t *testing.T) {
	tests := []struct {
		name         string
		setupMock    func(*common.MockCommandExecutor)
		groupService *MockGroupService
		wantOutput   string
	}{
		{
			name: "add user to groups success",
			setupMock: func(mock *common.MockCommandExecutor) {
				mock.SetResult(fmt.Sprintf("/usr/sbin/adduser --home /home/testuser --shell /bin/bash --uid %d --gid %d --gecos Test User --disabled-password testuser", 1001, 1001), 0, "User created", nil)
			},
			groupService: &MockGroupService{},
			wantOutput:   "User 'testuser' added successfully",
		},
		{
			name: "add user to groups failure",
			setupMock: func(mock *common.MockCommandExecutor) {
				mock.SetResult(fmt.Sprintf("/usr/sbin/adduser --home /home/testuser --shell /bin/bash --uid %d --gid %d --gecos Test User --disabled-password testuser", 1001, 1001), 0, "User created", nil)
			},
			groupService: &MockGroupService{AddUserToGroupsError: errors.New("failed to add to groups")},
			wantOutput:   "User 'testuser' created but failed to add to groups: failed to add to groups",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set platform like to debian for the test
			originalPlatformLike := utils.PlatformLike
			utils.SetPlatformLike("debian")
			t.Cleanup(func() {
				utils.SetPlatformLike(originalPlatformLike)
			})

			mock := common.NewMockCommandExecutor(t)
			if tt.setupMock != nil {
				tt.setupMock(mock)
			}

			handler := newTestUserHandler(mock, tt.groupService)
			ctx := context.Background()

			args := &common.CommandArgs{
				Username:      "testuser",
				UID:           1001,
				GID:           1001,
				Comment:       "Test User",
				HomeDirectory: "/home/testuser",
				Shell:         "/bin/bash",
				Groupname:     "testgroup",
				Groups:        []uint64{1002, 1003},
			}

			exitCode, output, err := handler.Execute(ctx, "adduser", args)

			// A group-add failure reaches the operator through the output, not err.
			assert.NoError(t, err)
			assert.Equal(t, 0, exitCode, "the create path exits 0 whether or not the group-add step fails")
			assert.Equal(t, tt.wantOutput, output)
			assert.True(t, tt.groupService.AddUserToGroupsCalled, "AddUserToGroups must run when the args carry additional groups")
		})
	}
}

// TestUserHandler_AddUser_Idempotent_ExistingUserSkipsCreate verifies that when
// the user already exists with a matching (or omitted) uid, adduser/useradd is
// NOT invoked, the command still succeeds, and the idempotent ensure step
// (AddUserToGroups) still runs so groups converge (issue #344, M8).
func TestUserHandler_AddUser_Idempotent_ExistingUserSkipsCreate(t *testing.T) {
	tests := []struct {
		name        string
		platform    string
		createCmd   string
		groupExists bool // whether the RHEL primary group already exists
	}{
		{name: "debian existing user", platform: "debian", createCmd: "/usr/sbin/adduser"},
		{name: "rhel existing user, group exists", platform: "rhel", createCmd: "/usr/sbin/useradd", groupExists: true},
		{name: "rhel existing user, group absent still ensured", platform: "rhel", createCmd: "/usr/sbin/useradd", groupExists: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			originalPlatformLike := utils.PlatformLike
			utils.SetPlatformLike(tt.platform)
			t.Cleanup(func() { utils.SetPlatformLike(originalPlatformLike) })

			mock := common.NewMockCommandExecutor(t)
			gs := &MockGroupService{}
			handler := newTestUserHandler(mock, gs)
			handler.lookupUser = common.ExistingUserLookup("1001") // present, uid matches request
			if tt.groupExists {
				handler.lookupGroup = common.ExistingGroupLookup("1001")
			} // else default AbsentGroupLookup

			args := &common.CommandArgs{
				Username:      "testuser",
				UID:           1001,
				GID:           1001,
				Comment:       "Test User",
				HomeDirectory: "/home/testuser",
				Shell:         "/bin/bash",
				Groupname:     "testgroup",
				Groups:        []uint64{1002, 1003},
			}

			exitCode, output, err := handler.Execute(context.Background(), "adduser", args)
			require.NoError(t, err)
			require.Equal(t, 0, exitCode, "output: %q", output)
			// The gate-detected idempotent path must report "already exists",
			// not the misleading "added successfully" (this is the crux #344 path).
			assert.Contains(t, output, "already exists")
			assert.NotContains(t, output, "added successfully")

			assert.False(t, mock.Invoked(tt.createCmd),
				"%s must not be invoked when the user already exists; got %+v", tt.createCmd, mock.GetExecutedCommands())
			// RHEL ensures the primary group; when it already exists, groupadd is skipped.
			if tt.platform == "rhel" {
				assert.Equal(t, !tt.groupExists, mock.Invoked("/usr/sbin/groupadd"),
					"groupadd runs exactly when the primary group is absent; got %+v", mock.GetExecutedCommands())
			}
			assert.True(t, gs.AddUserToGroupsCalled, "AddUserToGroups must still run for an existing user so groups converge")
		})
	}
}

// TestUserHandler_AddUser_Idempotent_UIDConflict verifies that a same-name
// user with a DIFFERENT uid is surfaced as a failure (real drift), never
// masked, and that no create command runs.
func TestUserHandler_AddUser_Idempotent_UIDConflict(t *testing.T) {
	for _, platform := range []string{"debian", "rhel"} {
		t.Run(platform, func(t *testing.T) {
			originalPlatformLike := utils.PlatformLike
			utils.SetPlatformLike(platform)
			t.Cleanup(func() { utils.SetPlatformLike(originalPlatformLike) })

			mock := common.NewMockCommandExecutor(t)
			handler := newTestUserHandler(mock, &MockGroupService{})
			handler.lookupUser = common.ExistingUserLookup("9999") // present but uid != requested

			args := &common.CommandArgs{
				Username:      "testuser",
				UID:           1001,
				GID:           1001,
				Comment:       "Test User",
				HomeDirectory: "/home/testuser",
				Shell:         "/bin/bash",
				Groupname:     "testgroup",
			}

			exitCode, output, _ := handler.Execute(context.Background(), "adduser", args)
			require.NotEqual(t, 0, exitCode, "a uid conflict must surface, output: %q", output)
			assert.Contains(t, output, "already exists with uid 9999", "the conflict message must name both uids")
			assert.Contains(t, output, "requested uid 1001", "the conflict message must name both uids")
			assert.False(t, mock.Invoked("/usr/sbin/adduser"),
				"no create command may run on a uid conflict; got %+v", mock.GetExecutedCommands())
			assert.False(t, mock.Invoked("/usr/sbin/useradd"),
				"no create command may run on a uid conflict; got %+v", mock.GetExecutedCommands())
		})
	}
}

// TestUserHandler_AddUser_Idempotent_ServiceAccountNameExists verifies that a
// service account (uid omitted, OS auto-assigns) treats name presence alone as
// "already provisioned" — no uid comparison, no useradd, success — AND that the
// load-bearing `groupadd -f` primary-group bootstrap STILL runs for the existing
// account (design intent #3: needed for utils.Demote(ValidateGroup=true)).
func TestUserHandler_AddUser_Idempotent_ServiceAccountNameExists(t *testing.T) {
	originalPlatformLike := utils.PlatformLike
	utils.SetPlatformLike("rhel")
	t.Cleanup(func() { utils.SetPlatformLike(originalPlatformLike) })

	mock := common.NewMockCommandExecutor(t)
	handler := newTestUserHandler(mock, &MockGroupService{})
	handler.lookupUser = common.ExistingUserLookup("4321") // any uid; must not be compared

	args := &common.CommandArgs{
		Username:         "gitlab-runner",
		Comment:          "GitLab Runner,,,,(alpacon-app)abc",
		Shell:            "/usr/sbin/nologin",
		Groupname:        "alpacon",
		IsServiceAccount: true,
	}

	exitCode, output, err := handler.Execute(context.Background(), "adduser", args)
	require.NoError(t, err)
	require.Equal(t, 0, exitCode, "output: %q", output)
	assert.False(t, mock.Invoked("/usr/sbin/useradd"), "useradd must not run when the service account already exists by name")
	// Load-bearing invariant: the `groupadd -f <Groupname>` bootstrap must run
	// even for an already-present service account, or the named primary group is
	// not ensured and Demote(ValidateGroup=true) breaks at websh runtime.
	assert.NotEqual(t, -1, invokedAt(mock, "/usr/sbin/groupadd", "-f", "alpacon"),
		"`groupadd -f alpacon` must still run for an existing service account; got %+v", mock.GetExecutedCommands())
}

// TestUserHandler_AddUser_Idempotent_LookupError verifies that a lookup error
// other than "not found" fails loud instead of blind-creating over a possibly
// shadowed entry.
func TestUserHandler_AddUser_Idempotent_LookupError(t *testing.T) {
	originalPlatformLike := utils.PlatformLike
	utils.SetPlatformLike("debian")
	t.Cleanup(func() { utils.SetPlatformLike(originalPlatformLike) })

	mock := common.NewMockCommandExecutor(t)
	handler := newTestUserHandler(mock, &MockGroupService{})
	handler.lookupUser = func(string) (*user.User, error) {
		return nil, errors.New("getpwnam_r: connection refused")
	}

	args := &common.CommandArgs{
		Username:      "testuser",
		UID:           1001,
		GID:           1001,
		Comment:       "Test User",
		HomeDirectory: "/home/testuser",
		Shell:         "/bin/bash",
		Groupname:     "testgroup",
	}

	exitCode, output, _ := handler.Execute(context.Background(), "adduser", args)
	require.NotEqual(t, 0, exitCode, "a failing lookup must surface, output: %q", output)
	assert.Contains(t, output, "unable to verify")
	assert.False(t, mock.Invoked("/usr/sbin/adduser"), "adduser must not run when existence cannot be verified")
}

// TestUserHandler_AddUser_SecondaryNet verifies the create-time reconcile net on
// the Debian adduser call site: when the up-front lookup reports absent but the
// create fails, a re-verify (plus an "already exists" tertiary fallback for
// NSS/LDAP names the pure-Go resolver cannot see) decides the outcome.
func TestUserHandler_AddUser_SecondaryNet(t *testing.T) {
	const adduserCmd = "/usr/sbin/adduser --home /home/testuser --shell /bin/bash --uid 1001 --gid 1001 --gecos Test User --disabled-password testuser"
	args := &common.CommandArgs{
		Username:      "testuser",
		UID:           1001,
		GID:           1001,
		Comment:       "Test User",
		HomeDirectory: "/home/testuser",
		Shell:         "/bin/bash",
		Groupname:     "testgroup",
	}

	tests := []struct {
		name         string
		createOutput string
		reverifyUID  string // uid returned on the second (reconcile) lookup; "" with reverifyErr means still-absent
		reverifyErr  error  // if set, reverify reports the user still not found
		wantExitZero bool
		wantMsgPart  string
	}{
		{name: "raced local create, matching uid -> idempotent success", createOutput: "adduser: user already exists", reverifyUID: "1001", wantExitZero: true, wantMsgPart: "already exists"},
		{name: "raced local create, different uid -> conflict surfaced", createOutput: "adduser: user already exists", reverifyUID: "2002", wantExitZero: false, wantMsgPart: "already exists with uid 2002"},
		{name: "NSS-backed same name, absent at reverify but create names this user -> tolerated", createOutput: "adduser: user 'testuser' already exists", reverifyErr: user.UnknownUserError("absent"), wantExitZero: true, wantMsgPart: "already exists"},
		{name: "uid-in-use by a different name, absent at reverify -> surfaced (not masked)", createOutput: "adduser: UID '1001' already exists", reverifyErr: user.UnknownUserError("absent"), wantExitZero: false, wantMsgPart: "UID '1001'"},
		{name: "genuine failure, absent and not already-exists -> surfaced", createOutput: "adduser: cannot create home directory", reverifyErr: user.UnknownUserError("absent"), wantExitZero: false, wantMsgPart: "cannot create home directory"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			originalPlatformLike := utils.PlatformLike
			utils.SetPlatformLike("debian")
			t.Cleanup(func() { utils.SetPlatformLike(originalPlatformLike) })

			mock := common.NewMockCommandExecutor(t)
			mock.SetResult(adduserCmd, 1, tt.createOutput, errors.New("exit status 1"))
			handler := newTestUserHandler(mock, &MockGroupService{})

			calls := 0
			handler.lookupUser = func(name string) (*user.User, error) {
				calls++
				if calls == 1 {
					return nil, user.UnknownUserError("absent") // gate: absent -> create attempted
				}
				if tt.reverifyErr != nil {
					return nil, tt.reverifyErr
				}
				return &user.User{Username: name, Uid: tt.reverifyUID}, nil
			}

			exitCode, output, _ := handler.Execute(context.Background(), "adduser", args)
			require.True(t, mock.Invoked("/usr/sbin/adduser"), "adduser must be attempted after an absent gate lookup")
			if tt.wantExitZero {
				require.Equal(t, 0, exitCode, "the reconcile must land on idempotent success, output: %q", output)
			} else {
				require.NotEqual(t, 0, exitCode, "output: %q", output)
			}
			if tt.wantMsgPart != "" {
				assert.Contains(t, output, tt.wantMsgPart)
			}
		})
	}
}

// TestUserHandler_AddUser_Rhel_SecondaryNet exercises the reconcile net at the
// RHEL call sites (user.go useradd and primary-group groupadd), which the Debian
// test above does not reach. These sites have distinct argument wiring, so a
// copy-paste defect there would otherwise be uncaught (masking drift on RHEL).
func TestUserHandler_AddUser_Rhel_SecondaryNet(t *testing.T) {
	// A simple comment keeps the useradd command key predictable.
	baseArgs := func() *common.CommandArgs {
		return &common.CommandArgs{
			Username:      "john",
			UID:           5001,
			GID:           5001,
			Comment:       "John",
			HomeDirectory: "/home/john",
			Shell:         "/bin/bash",
			Groupname:     "alpacon",
		}
	}
	const useraddCmd = "/usr/sbin/useradd --home-dir /home/john --shell /bin/bash --uid 5001 --gid 5001 --comment John --create-home john"
	const groupaddCmd = "/usr/sbin/groupadd --gid 5001 alpacon"

	t.Run("useradd reconcile: raced matching uid -> idempotent success", func(t *testing.T) {
		originalPlatformLike := utils.PlatformLike
		utils.SetPlatformLike("rhel")
		t.Cleanup(func() { utils.SetPlatformLike(originalPlatformLike) })

		mock := common.NewMockCommandExecutor(t)
		mock.SetResult(useraddCmd, 1, "useradd: user 'john' already exists", errors.New("exit status 9"))
		handler := newTestUserHandler(mock, &MockGroupService{})
		handler.lookupGroup = common.ExistingGroupLookup("5001") // group present -> groupadd skipped

		calls := 0
		handler.lookupUser = func(name string) (*user.User, error) {
			calls++
			if calls == 1 {
				return nil, user.UnknownUserError("absent") // gate
			}
			return &user.User{Username: name, Uid: "5001"}, nil // reverify: matches
		}

		exitCode, output, _ := handler.Execute(context.Background(), "adduser", baseArgs())
		require.True(t, mock.Invoked("/usr/sbin/useradd"), "useradd must be attempted")
		require.Equal(t, 0, exitCode, "the reconcile must land on idempotent success, output: %q", output)
		assert.Contains(t, output, "already exists", "the reconciled-success path must say so")
	})

	t.Run("useradd reconcile: raced different uid -> conflict surfaced", func(t *testing.T) {
		originalPlatformLike := utils.PlatformLike
		utils.SetPlatformLike("rhel")
		t.Cleanup(func() { utils.SetPlatformLike(originalPlatformLike) })

		mock := common.NewMockCommandExecutor(t)
		mock.SetResult(useraddCmd, 1, "useradd: user 'john' already exists", errors.New("exit status 9"))
		handler := newTestUserHandler(mock, &MockGroupService{})
		handler.lookupGroup = common.ExistingGroupLookup("5001")

		calls := 0
		handler.lookupUser = func(name string) (*user.User, error) {
			calls++
			if calls == 1 {
				return nil, user.UnknownUserError("absent")
			}
			return &user.User{Username: name, Uid: "6006"}, nil // reverify: uid mismatch
		}

		exitCode, output, _ := handler.Execute(context.Background(), "adduser", baseArgs())
		require.NotEqual(t, 0, exitCode, "the uid conflict must surface, output: %q", output)
		assert.Contains(t, output, "already exists with uid 6006")
	})

	t.Run("primary-group groupadd reconcile: raced NSS group -> tolerated, useradd proceeds", func(t *testing.T) {
		originalPlatformLike := utils.PlatformLike
		utils.SetPlatformLike("rhel")
		t.Cleanup(func() { utils.SetPlatformLike(originalPlatformLike) })

		mock := common.NewMockCommandExecutor(t)
		mock.SetResult(groupaddCmd, 1, "groupadd: group 'alpacon' already exists", errors.New("exit status 9"))
		handler := newTestUserHandler(mock, &MockGroupService{}) // absentUser -> useradd runs

		gcalls := 0
		handler.lookupGroup = func(name string) (*user.Group, error) {
			gcalls++
			if gcalls == 1 {
				return nil, user.UnknownGroupError("absent") // gate: absent -> groupadd attempted
			}
			return &user.Group{Name: name, Gid: "5001"}, nil // reverify: present, gid matches
		}

		exitCode, output, err := handler.Execute(context.Background(), "adduser", baseArgs())
		require.NoError(t, err, "the groupadd reconcile must tolerate a raced group")
		require.Equal(t, 0, exitCode, "output: %q", output)
		require.True(t, mock.Invoked("/usr/sbin/groupadd"), "groupadd must be attempted after an absent gate lookup")
		assert.True(t, mock.Invoked("/usr/sbin/useradd"), "useradd must still run after the primary group is reconciled")
	})
}

// TestUserHandler_AddUser_Rhel_PrimaryGroupGate verifies the RHEL primary-group
// groupadd is gated by the same lookup rule as standalone addgroup (A-3
// consistency): existing+match skips groupadd, existing+mismatch surfaces a
// conflict before useradd runs.
func TestUserHandler_AddUser_Rhel_PrimaryGroupGate(t *testing.T) {
	baseArgs := func() *common.CommandArgs {
		return &common.CommandArgs{
			Username:      "john",
			UID:           5001,
			GID:           5001,
			Comment:       "John,,,,(alpacon)uuid",
			HomeDirectory: "/home/john",
			Shell:         "/bin/bash",
			Groupname:     "alpacon",
		}
	}

	t.Run("group exists with matching gid -> groupadd skipped, useradd runs", func(t *testing.T) {
		originalPlatformLike := utils.PlatformLike
		utils.SetPlatformLike("rhel")
		t.Cleanup(func() { utils.SetPlatformLike(originalPlatformLike) })

		mock := common.NewMockCommandExecutor(t)
		handler := newTestUserHandler(mock, &MockGroupService{}) // absentUser -> useradd runs
		handler.lookupGroup = common.ExistingGroupLookup("5001")

		exitCode, output, err := handler.Execute(context.Background(), "adduser", baseArgs())
		require.NoError(t, err)
		require.Equal(t, 0, exitCode, "output: %q", output)
		assert.False(t, mock.Invoked("/usr/sbin/groupadd"),
			"groupadd must be skipped when the group already exists with a matching gid; got %+v", mock.GetExecutedCommands())
		assert.True(t, mock.Invoked("/usr/sbin/useradd"), "useradd must still run to create the absent user")
	})

	t.Run("group exists with different gid -> conflict before useradd", func(t *testing.T) {
		originalPlatformLike := utils.PlatformLike
		utils.SetPlatformLike("rhel")
		t.Cleanup(func() { utils.SetPlatformLike(originalPlatformLike) })

		mock := common.NewMockCommandExecutor(t)
		handler := newTestUserHandler(mock, &MockGroupService{})
		handler.lookupGroup = common.ExistingGroupLookup("7777")

		exitCode, output, _ := handler.Execute(context.Background(), "adduser", baseArgs())
		require.NotEqual(t, 0, exitCode, "a group gid conflict must surface, output: %q", output)
		assert.Contains(t, output, "already exists with gid 7777")
		assert.False(t, mock.Invoked("/usr/sbin/useradd"), "useradd must not run when the primary group gid conflicts")
	})
}

// TestUserHandler_AddUser_ExistingUser_GroupAddSoftFailMessage verifies the
// AddUserToGroups soft-failure message reflects that the user already existed
// (not "created") on the re-provision path.
func TestUserHandler_AddUser_ExistingUser_GroupAddSoftFailMessage(t *testing.T) {
	originalPlatformLike := utils.PlatformLike
	utils.SetPlatformLike("debian")
	t.Cleanup(func() { utils.SetPlatformLike(originalPlatformLike) })

	mock := common.NewMockCommandExecutor(t)
	gs := &MockGroupService{AddUserToGroupsError: errors.New("usermod failed")}
	handler := newTestUserHandler(mock, gs)
	handler.lookupUser = common.ExistingUserLookup("1001") // user already exists

	args := &common.CommandArgs{
		Username:      "testuser",
		UID:           1001,
		GID:           1001,
		Comment:       "Test User",
		HomeDirectory: "/home/testuser",
		Shell:         "/bin/bash",
		Groupname:     "testgroup",
		Groups:        []uint64{1002},
	}

	exitCode, output, err := handler.Execute(context.Background(), "adduser", args)
	require.NoError(t, err)
	require.Equal(t, 0, exitCode, "a group-add soft failure must keep exit 0, output: %q", output)
	assert.True(t, gs.AddUserToGroupsCalled, "AddUserToGroups must be called for an existing user")
	assert.NotContains(t, output, "created", "the soft-failure message must not claim the user was created")
	assert.Contains(t, output, "already exists but failed to add to groups")
	assert.False(t, mock.Invoked("/usr/sbin/adduser"), "adduser must not run for an existing user")
}
