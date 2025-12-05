package user

import (
	"context"
	"errors"
	"fmt"
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
				// Missing other required fields
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
