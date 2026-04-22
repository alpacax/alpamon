package user

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/alpacax/alpamon/pkg/executor/handlers/common"
	"github.com/alpacax/alpamon/pkg/utils"
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

			handler := NewUserHandler(mock, tt.groupService, nil)
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
		// UID, GID, HomeDirectory intentionally omitted — OS auto-assigns
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
			forbidFlags: []string{"--uid", "--gid", "--home-dir"},
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
			handler := NewUserHandler(mock, &MockGroupService{}, nil)

			exitCode, _, err := handler.Execute(context.Background(), "adduser", baseArgs)
			if err != nil {
				t.Fatalf("Execute() unexpected error: %v", err)
			}
			if exitCode != 0 {
				t.Fatalf("Execute() exitCode = %d, want 0", exitCode)
			}

			executed := mock.GetExecutedCommands()
			var target *common.ExecutedCommand
			var sawGidGroupadd, sawGroupaddDashF, sawUsermodAppendGroup bool
			for i := range executed {
				c := executed[i]
				if c.Name == tt.wantProgram {
					target = &executed[i]
				}
				if c.Name == "/usr/sbin/groupadd" {
					joined := strings.Join(c.Args, " ")
					if strings.Contains(joined, "--gid") {
						sawGidGroupadd = true
					}
					if len(c.Args) >= 2 && c.Args[0] == "-f" && c.Args[1] == "alpacon" {
						sawGroupaddDashF = true
					}
				}
				if c.Name == "/usr/sbin/usermod" && len(c.Args) >= 3 &&
					c.Args[0] == "-aG" && c.Args[1] == "alpacon" && c.Args[2] == "gitlab-runner" {
					sawUsermodAppendGroup = true
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
			// (that path is for IAM User only) but MUST add the user to the
			// requested Groupname via `groupadd -f` + `usermod -aG` so later
			// privilege demotion (ValidateGroup=true) succeeds.
			if sawGidGroupadd {
				t.Error("service account path must not call groupadd with --gid")
			}
			if !sawGroupaddDashF {
				t.Error("expected `groupadd -f alpacon` to ensure the supplementary group exists")
			}
			if !sawUsermodAppendGroup {
				t.Error("expected `usermod -aG alpacon gitlab-runner` to set supplementary membership")
			}
		})
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
	handler := NewUserHandler(mock, &MockGroupService{}, nil)

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
	handler := NewUserHandler(common.NewMockCommandExecutor(t), &MockGroupService{}, nil)

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
				// UID/GID/HomeDirectory missing — must fail
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
				// IsServiceAccount=false — uid=0 must be rejected
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

			handler := NewUserHandler(mock, tt.groupService, nil)
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
