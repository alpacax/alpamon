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
	"strings"
	"testing"

	"github.com/alpacax/alpamon/v2/pkg/executor/handlers/common"
	"github.com/alpacax/alpamon/v2/pkg/utils"
)

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
		wantErr      bool
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
				Groups:        []uint64{1002, 1003},
			},
			setupMock: func(mock *common.MockCommandExecutor) {
				mock.SetResult(fmt.Sprintf("/usr/sbin/adduser --home /home/testuser --shell /bin/bash --uid %d --gid %d --gecos Test User --disabled-password testuser", 1001, 1001), 0, "User created", nil)
			},
			groupService: &MockGroupService{},
			wantCode:     0,
			wantErr:      false,
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
			wantErr:      false,
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
			wantErr:      false,
		},
		{
			name:         "unknown command",
			cmd:          "unknownuser",
			args:         &common.CommandArgs{},
			groupService: &MockGroupService{},
			wantCode:     1,
			wantErr:      true,
		},
		{
			name: "adduser missing username",
			cmd:  "adduser",
			args: &common.CommandArgs{
				UID: 1001,
				GID: 1001,
			},
			groupService: &MockGroupService{},
			wantCode:     1,
			wantErr:      false,
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
			wantErr:      true, // error is returned as part of output, not actual go error
		},
	}

	for _, tt := range tests {
		tt := tt // Capture range variable.
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

			if (err != nil) != tt.wantErr {
				t.Errorf("Execute() error = %v, wantErr %v", err, tt.wantErr)
			}
			if exitCode != tt.wantCode {
				t.Errorf("Execute() exitCode = %v, want %v", exitCode, tt.wantCode)
			}
			if exitCode == 0 && output == "" && !tt.wantErr {
				t.Error("Execute() returned success but no output")
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
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			originalPlatformLike := utils.PlatformLike
			utils.SetPlatformLike(tt.platform)
			t.Cleanup(func() {
				utils.SetPlatformLike(originalPlatformLike)
			})

			mock := common.NewMockCommandExecutor(t)
			handler := newTestUserHandler(mock, &MockGroupService{})

			exitCode, _, err := handler.Execute(context.Background(), "adduser", baseArgs)
			if err != nil {
				t.Fatalf("Execute() unexpected error: %v", err)
			}
			if exitCode != 0 {
				t.Fatalf("Execute() exitCode = %d, want 0", exitCode)
			}

			executed := mock.GetExecutedCommands()
			var target *common.ExecutedCommand
			var sawGidGroupadd, sawGroupaddDashF, sawUsermod bool
			var groupaddDashFIndex, useraddIndex = -1, -1
			for i := range executed {
				c := executed[i]
				if c.Name == tt.wantProgram {
					target = &executed[i]
					useraddIndex = i
				}
				if c.Name == "/usr/sbin/groupadd" {
					joined := strings.Join(c.Args, " ")
					if strings.Contains(joined, "--gid") {
						sawGidGroupadd = true
					}
					if len(c.Args) >= 2 && c.Args[0] == "-f" && c.Args[1] == "alpacon" {
						sawGroupaddDashF = true
						groupaddDashFIndex = i
					}
				}
				if c.Name == "/usr/sbin/usermod" {
					sawUsermod = true
				}
			}

			if target == nil {
				t.Fatalf("expected %s to be invoked, got commands: %+v", tt.wantProgram, executed)
			}
			joined := strings.Join(target.Args, " ")
			for _, want := range tt.wantFlags {
				if !strings.Contains(joined, want) {
					t.Errorf("expected flag %q in args, got: %s", want, joined)
				}
			}
			for _, forbid := range tt.forbidFlags {
				for _, a := range target.Args {
					if a == forbid {
						t.Errorf("flag %q must not appear in args, got: %s", forbid, joined)
					}
				}
			}

			// Service account must NOT use the gid-based groupadd path
			// (that path is for IAM User only). It MUST run `groupadd -f
			// alpacon` BEFORE adduser/useradd so the named group exists,
			// and adduser/useradd MUST set the primary group by name
			// (--ingroup on Debian, --gid <name> on RHEL). Post-fact
			// `usermod -aG` is no longer used.
			if sawGidGroupadd {
				t.Error("service account path must not call groupadd with --gid")
			}
			if !sawGroupaddDashF {
				t.Error("expected `groupadd -f alpacon` to ensure the named primary group exists")
			}
			if groupaddDashFIndex >= 0 && useraddIndex >= 0 && groupaddDashFIndex >= useraddIndex {
				t.Errorf("`groupadd -f` must run BEFORE %s, got order groupadd=%d useradd=%d",
					tt.wantProgram, groupaddDashFIndex, useraddIndex)
			}
			if sawUsermod {
				t.Error("post-fact `usermod` should no longer run; primary group is set during adduser/useradd")
			}

			// Verify the primary-group-by-name flag is on the create command itself.
			switch tt.platform {
			case "debian":
				if !strings.Contains(joined, "--ingroup alpacon") {
					t.Errorf("expected `--ingroup alpacon` on adduser, got: %s", joined)
				}
			case "rhel":
				if !strings.Contains(joined, "--gid alpacon") {
					t.Errorf("expected `--gid alpacon` on useradd, got: %s", joined)
				}
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
	if err != nil {
		t.Fatalf("Execute() unexpected error: %v", err)
	}
	if exitCode != 0 {
		t.Fatalf("Execute() exitCode = %d, want 0", exitCode)
	}

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
	if useradd == nil {
		t.Fatalf("expected useradd to be invoked; got %+v", executed)
	}
	joined := strings.Join(useradd.Args, " ")
	for _, want := range []string{"--uid", "7000", "--gid", "7000", "--home-dir", "/var/lib/explicit-svc"} {
		if !strings.Contains(joined, want) {
			t.Errorf("expected flag %q on useradd (explicit values must be honored), got: %s", want, joined)
		}
	}
	if sawNamedGidUseradd {
		t.Error("when GID is explicit (non-zero), useradd must NOT use the by-name `--gid alpacon` path")
	}
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
	if exitCode == 0 {
		t.Fatalf("expected non-zero exit code when groupadd fails on service-account path, got 0; output=%q", output)
	}

	// useradd must not be reached if the primary group cannot be ensured.
	for _, c := range mock.GetExecutedCommands() {
		if c.Name == "/usr/sbin/useradd" {
			t.Errorf("useradd must not run when `groupadd -f` failed; got args=%v", c.Args)
		}
	}
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
	if err != nil {
		t.Fatalf("Execute() unexpected error: %v", err)
	}
	if exitCode != 0 {
		t.Fatalf("Execute() exitCode = %d, want 0", exitCode)
	}

	executed := mock.GetExecutedCommands()
	var sawGroupadd, sawUseradd bool
	for _, c := range executed {
		if c.Name == "/usr/sbin/groupadd" {
			sawGroupadd = true
			joined := strings.Join(c.Args, " ")
			if !strings.Contains(joined, "--gid 5001") || !strings.Contains(joined, "alpacon") {
				t.Errorf("groupadd missing expected args: %s", joined)
			}
		}
		if c.Name == "/usr/sbin/useradd" {
			sawUseradd = true
			joined := strings.Join(c.Args, " ")
			for _, want := range []string{"--uid", "5001", "--gid", "--home-dir", "/home/john", "--shell", "/bin/bash", "--create-home", "john"} {
				if !strings.Contains(joined, want) {
					t.Errorf("useradd missing %q: %s", want, joined)
				}
			}
		}
	}
	if !sawGroupadd {
		t.Error("expected groupadd to be invoked")
	}
	if !sawUseradd {
		t.Error("expected useradd to be invoked")
	}
}

func TestUserHandler_Validate(t *testing.T) {
	handler := newTestUserHandler(common.NewMockCommandExecutor(t), &MockGroupService{})

	tests := []struct {
		name    string
		cmd     string
		args    *common.CommandArgs
		wantErr bool
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
			wantErr: false,
		},
		{
			name: "adduser missing required fields",
			cmd:  "adduser",
			args: &common.CommandArgs{
				Username: "testuser",
				// IsServiceAccount=false (default), so UID/GID/HomeDirectory
				// are required_unless and also missing. Comment/Groupname are
				// required unconditionally. Shell is defaulted by the helper.
			},
			wantErr: true,
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
			wantErr: false,
		},
		{
			name: "adduser IAM User path must still require uid/gid/home",
			cmd:  "adduser",
			args: &common.CommandArgs{
				Username:  "john",
				Comment:   "John,,,,(alpacon)uuid",
				Shell:     "/bin/bash",
				Groupname: "alpacon",
				// IsServiceAccount=false (default)
				// UID/GID/HomeDirectory missing: must fail
			},
			wantErr: true,
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
			wantErr: true,
		},
		{
			name: "deluser valid",
			cmd:  "deluser",
			args: &common.CommandArgs{
				Username: "testuser",
			},
			wantErr: false,
		},
		{
			name: "moduser valid",
			cmd:  "moduser",
			args: &common.CommandArgs{
				Username:   "testuser",
				Groupnames: []string{"sudo"},
				Comment:    "Updated",
			},
			wantErr: false,
		},
		{
			name:    "unknown command",
			cmd:     "unknown",
			args:    &common.CommandArgs{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := handler.Validate(tt.cmd, tt.args)
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestUserHandler_AddUserWithGroups(t *testing.T) {
	tests := []struct {
		name         string
		setupMock    func(*common.MockCommandExecutor)
		groupService *MockGroupService
		wantCode     int
		calledGroups bool
	}{
		{
			name: "add user to groups success",
			setupMock: func(mock *common.MockCommandExecutor) {
				mock.SetResult(fmt.Sprintf("/usr/sbin/adduser --home /home/testuser --shell /bin/bash --uid %d --gid %d --gecos Test User --disabled-password testuser", 1001, 1001), 0, "User created", nil)
			},
			groupService: &MockGroupService{},
			wantCode:     0,
			calledGroups: true,
		},
		{
			name: "add user to groups failure",
			setupMock: func(mock *common.MockCommandExecutor) {
				mock.SetResult(fmt.Sprintf("/usr/sbin/adduser --home /home/testuser --shell /bin/bash --uid %d --gid %d --gecos Test User --disabled-password testuser", 1001, 1001), 0, "User created", nil)
			},
			groupService: &MockGroupService{AddUserToGroupsError: errors.New("failed to add to groups")},
			wantCode:     0, // Still want 0 for user creation, group error is logged
			calledGroups: true,
		},
	}

	for _, tt := range tests {
		tt := tt // Capture range variable.
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

			exitCode, _, err := handler.Execute(ctx, "adduser", args)

			if err != nil && !tt.groupService.AddUserToGroupsCalled { // only expect error if AddUserToGroups not called
				t.Errorf("Execute() unexpected error: %v", err)
			}
			if exitCode != tt.wantCode {
				t.Errorf("Execute() exitCode = %v, want %v", exitCode, tt.wantCode)
			}
			if tt.calledGroups && !tt.groupService.AddUserToGroupsCalled {
				t.Error("Execute() did not call AddUserToGroups on group service")
			}
			if !tt.calledGroups && tt.groupService.AddUserToGroupsCalled {
				t.Error("Execute() unexpectedly called AddUserToGroups on group service")
			}
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
			if err != nil {
				t.Fatalf("Execute() unexpected error: %v", err)
			}
			if exitCode != 0 {
				t.Fatalf("Execute() exitCode = %d, want 0 (output=%q)", exitCode, output)
			}

			if mock.Invoked(tt.createCmd) {
				t.Errorf("%s must NOT be invoked when the user already exists; got %+v", tt.createCmd, mock.GetExecutedCommands())
			}
			// RHEL ensures the primary group; when it already exists, groupadd is skipped.
			if tt.platform == "rhel" {
				sawGroupadd := mock.Invoked("/usr/sbin/groupadd")
				if tt.groupExists && sawGroupadd {
					t.Errorf("groupadd must be skipped when the group already exists with matching gid; got %+v", mock.GetExecutedCommands())
				}
				if !tt.groupExists && !sawGroupadd {
					t.Errorf("groupadd must run to ensure the primary group exists; got %+v", mock.GetExecutedCommands())
				}
			}
			if !gs.AddUserToGroupsCalled {
				t.Error("AddUserToGroups must still run for an existing user so groups converge")
			}
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
			if exitCode == 0 {
				t.Fatalf("expected non-zero exit for uid conflict, got 0 (output=%q)", output)
			}
			if !strings.Contains(output, "already exists with uid 9999") || !strings.Contains(output, "requested uid 1001") {
				t.Errorf("conflict message must name both uids, got: %q", output)
			}
			if mock.Invoked("/usr/sbin/adduser") || mock.Invoked("/usr/sbin/useradd") {
				t.Errorf("no create command may run on a uid conflict; got %+v", mock.GetExecutedCommands())
			}
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
	if err != nil {
		t.Fatalf("Execute() unexpected error: %v", err)
	}
	if exitCode != 0 {
		t.Fatalf("Execute() exitCode = %d, want 0 (output=%q)", exitCode, output)
	}
	if mock.Invoked("/usr/sbin/useradd") {
		t.Error("useradd must not run when the service account already exists by name")
	}
	// Load-bearing invariant: the `groupadd -f <Groupname>` bootstrap must run
	// even for an already-present service account, or the named primary group is
	// not ensured and Demote(ValidateGroup=true) breaks at websh runtime.
	sawGroupaddDashF := false
	for _, c := range mock.GetExecutedCommands() {
		if c.Name == "/usr/sbin/groupadd" && len(c.Args) >= 2 && c.Args[0] == "-f" && c.Args[1] == "alpacon" {
			sawGroupaddDashF = true
		}
	}
	if !sawGroupaddDashF {
		t.Errorf("`groupadd -f alpacon` must still run for an existing service account; got %+v", mock.GetExecutedCommands())
	}
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
	if exitCode == 0 {
		t.Fatalf("expected non-zero exit when the lookup itself fails, got 0 (output=%q)", output)
	}
	if !strings.Contains(output, "unable to verify") {
		t.Errorf("expected an 'unable to verify' message, got: %q", output)
	}
	if mock.Invoked("/usr/sbin/adduser") {
		t.Error("adduser must not run when existence cannot be verified")
	}
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
			if !mock.Invoked("/usr/sbin/adduser") {
				t.Fatal("adduser should have been attempted after an absent gate lookup")
			}
			if tt.wantExitZero && exitCode != 0 {
				t.Fatalf("expected idempotent success (exit 0), got %d (output=%q)", exitCode, output)
			}
			if !tt.wantExitZero && exitCode == 0 {
				t.Fatalf("expected non-zero exit, got 0 (output=%q)", output)
			}
			if tt.wantMsgPart != "" && !strings.Contains(output, tt.wantMsgPart) {
				t.Errorf("expected output to contain %q, got: %q", tt.wantMsgPart, output)
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
		if !mock.Invoked("/usr/sbin/useradd") {
			t.Fatal("useradd should have been attempted")
		}
		if exitCode != 0 {
			t.Fatalf("expected idempotent success, got %d (output=%q)", exitCode, output)
		}
		if !strings.Contains(output, "already exists") {
			t.Errorf("reconciled-success path should report 'already exists', got: %q", output)
		}
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
		if exitCode == 0 {
			t.Fatalf("expected conflict (non-zero), got 0 (output=%q)", output)
		}
		if !strings.Contains(output, "already exists with uid 6006") {
			t.Errorf("expected uid conflict message, got: %q", output)
		}
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
		if err != nil || exitCode != 0 {
			t.Fatalf("expected groupadd reconcile to tolerate; got exitCode=%d err=%v output=%q", exitCode, err, output)
		}
		if !mock.Invoked("/usr/sbin/groupadd") {
			t.Fatal("groupadd should have been attempted after an absent gate lookup")
		}
		if !mock.Invoked("/usr/sbin/useradd") {
			t.Error("useradd must still run after the primary group is reconciled")
		}
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
		if err != nil || exitCode != 0 {
			t.Fatalf("Execute() exitCode=%d err=%v output=%q", exitCode, err, output)
		}
		if mock.Invoked("/usr/sbin/groupadd") {
			t.Errorf("groupadd must be skipped when the group already exists with matching gid; got %+v", mock.GetExecutedCommands())
		}
		if !mock.Invoked("/usr/sbin/useradd") {
			t.Error("useradd must still run to create the absent user")
		}
	})

	t.Run("group exists with different gid -> conflict before useradd", func(t *testing.T) {
		originalPlatformLike := utils.PlatformLike
		utils.SetPlatformLike("rhel")
		t.Cleanup(func() { utils.SetPlatformLike(originalPlatformLike) })

		mock := common.NewMockCommandExecutor(t)
		handler := newTestUserHandler(mock, &MockGroupService{})
		handler.lookupGroup = common.ExistingGroupLookup("7777")

		exitCode, output, _ := handler.Execute(context.Background(), "adduser", baseArgs())
		if exitCode == 0 {
			t.Fatalf("expected non-zero exit for group gid conflict, got 0 (output=%q)", output)
		}
		if !strings.Contains(output, "already exists with gid 7777") {
			t.Errorf("expected group conflict message, got: %q", output)
		}
		if mock.Invoked("/usr/sbin/useradd") {
			t.Error("useradd must not run when the primary group gid conflicts")
		}
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
	if err != nil {
		t.Fatalf("Execute() unexpected error: %v", err)
	}
	if exitCode != 0 {
		t.Fatalf("group-add soft failure must keep exit 0, got %d (output=%q)", exitCode, output)
	}
	if !gs.AddUserToGroupsCalled {
		t.Error("AddUserToGroups should have been called for an existing user")
	}
	if strings.Contains(output, "created") || !strings.Contains(output, "already exists but failed to add to groups") {
		t.Errorf("soft-failure message should say the user already exists, not 'created'; got: %q", output)
	}
	if mock.Invoked("/usr/sbin/adduser") {
		t.Error("adduser must not run for an existing user")
	}
}
