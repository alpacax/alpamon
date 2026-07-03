//go:build !windows

// Group management is unsupported on Windows (see pkg/executor/factory_windows.go:
// GroupHandler is not registered there). These assertions hardcode
// /usr/sbin/addgroup invocations, so they are Unix-only. Tracked in alpamon
// issue #284 under "excluded test packages".

package group

import (
	"context"
	"errors"
	"os/user"
	"strings"
	"testing"

	"github.com/alpacax/alpamon/v2/pkg/executor/handlers/common"
	"github.com/alpacax/alpamon/v2/pkg/utils"
)

// newTestGroupHandler builds a GroupHandler whose lookup reports absent by
// default (via the shared fake in common/testing.go). Individual tests override
// h.lookupGroup for the exists/conflict matrix.
func newTestGroupHandler(exec common.CommandExecutor) *GroupHandler {
	h := NewGroupHandler(exec, nil)
	h.lookupGroup = common.AbsentGroupLookup
	return h
}

func TestGroupHandler_AddGroup(t *testing.T) {
	// Create mock executor
	mockExec := common.NewMockCommandExecutor(t)
	mockExec.SetResult("/usr/sbin/addgroup --gid 1001 testgroup", 0, "Group added successfully", nil)

	// Create handler with mock
	handler := NewGroupHandler(mockExec, nil)

	// Test data
	args := &common.CommandArgs{
		Groupname: "testgroup",
		GID:       1001,
	}

	// Validate arguments
	err := handler.Validate("addgroup", args)
	if err != nil {
		t.Fatalf("Validation failed: %v", err)
	}

	// Execute command (Note: This test is simplified, full implementation would use proper mocking)
	// For now, just test validation and basic structure
	t.Log("Group handler validated successfully")
}

func TestGroupHandler_AddGroup_InvalidArgs(t *testing.T) {
	handler := NewGroupHandler(nil, nil) // NewGroupHandler expects common.CommandExecutor, but for validation only, nil is fine

	testCases := []struct {
		name    string
		args    *common.CommandArgs
		wantErr bool
	}{
		{
			name: "missing groupname",
			args: &common.CommandArgs{
				GID: 1001,
			},
			wantErr: true,
		},
		{
			name: "missing GID",
			args: &common.CommandArgs{
				Groupname: "testgroup",
			},
			wantErr: true,
		},
		{
			name: "invalid GID",
			args: &common.CommandArgs{
				Groupname: "testgroup",
				GID:       0,
			},
			wantErr: true,
		},
		{
			name: "valid args",
			args: &common.CommandArgs{
				Groupname: "testgroup",
				GID:       1001,
			},
			wantErr: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := handler.Validate("addgroup", tc.args)
			if (err != nil) != tc.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

func TestGroupHandler_DelGroup(t *testing.T) {
	handler := NewGroupHandler(nil, nil) // NewGroupHandler expects common.CommandExecutor, but for validation only, nil is fine

	// Test validation for delgroup
	args := &common.CommandArgs{
		Groupname: "testgroup",
	}

	err := handler.Validate("delgroup", args)
	if err != nil {
		t.Fatalf("Validation failed: %v", err)
	}

	// Test missing groupname
	emptyArgs := &common.CommandArgs{}
	err = handler.Validate("delgroup", emptyArgs)
	if err == nil {
		t.Error("Expected error for missing groupname, got nil")
	}
}

func TestGroupHandler_Commands(t *testing.T) {
	handler := NewGroupHandler(nil, nil) // NewGroupHandler expects common.CommandExecutor, but for validation only, nil is fine

	commands := handler.Commands()
	expectedCommands := []string{"addgroup", "delgroup"}

	if len(commands) != len(expectedCommands) {
		t.Errorf("Expected %d commands, got %d", len(expectedCommands), len(commands))
	}

	for i, cmd := range expectedCommands {
		if commands[i] != cmd {
			t.Errorf("Expected command %s at index %d, got %s", cmd, i, commands[i])
		}
	}
}

func TestGroupHandler_Name(t *testing.T) {
	handler := NewGroupHandler(nil, nil) // NewGroupHandler expects common.CommandExecutor, but for validation only, nil is fine

	if handler.Name() != "group" {
		t.Errorf("Expected handler name 'group', got '%s'", handler.Name())
	}
}

// TestGroupHandler_AddGroup_Execute exercises handleAddGroup end-to-end for the
// absent (create) path on both platforms.
func TestGroupHandler_AddGroup_Execute(t *testing.T) {
	tests := []struct {
		name       string
		platform   string
		createCmd  string
		createArgs string
	}{
		{name: "debian addgroup", platform: "debian", createCmd: "/usr/sbin/addgroup", createArgs: "--gid 1001 testgroup"},
		{name: "rhel groupadd", platform: "rhel", createCmd: "/usr/sbin/groupadd", createArgs: "--gid 1001 testgroup"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			originalPlatformLike := utils.PlatformLike
			utils.SetPlatformLike(tt.platform)
			t.Cleanup(func() { utils.SetPlatformLike(originalPlatformLike) })

			mock := common.NewMockCommandExecutor(t)
			mock.SetResult(tt.createCmd+" "+tt.createArgs, 0, "Group created", nil)
			handler := newTestGroupHandler(mock) // AbsentGroupLookup -> create path

			args := &common.CommandArgs{Groupname: "testgroup", GID: 1001}
			exitCode, output, err := handler.Execute(context.Background(), "addgroup", args)
			if err != nil || exitCode != 0 {
				t.Fatalf("Execute() exitCode=%d err=%v output=%q", exitCode, err, output)
			}
			if !mock.Invoked(tt.createCmd) {
				t.Errorf("expected %s to be invoked; got %+v", tt.createCmd, mock.GetExecutedCommands())
			}
		})
	}
}

// TestGroupHandler_AddGroup_Idempotent covers the exists/conflict/lookup-error
// matrix (issue #344, M8).
func TestGroupHandler_AddGroup_Idempotent(t *testing.T) {
	t.Run("exists with matching gid -> skip create, success", func(t *testing.T) {
		originalPlatformLike := utils.PlatformLike
		utils.SetPlatformLike("debian")
		t.Cleanup(func() { utils.SetPlatformLike(originalPlatformLike) })

		mock := common.NewMockCommandExecutor(t)
		handler := newTestGroupHandler(mock)
		handler.lookupGroup = common.ExistingGroupLookup("1001")

		exitCode, output, err := handler.Execute(context.Background(), "addgroup", &common.CommandArgs{Groupname: "testgroup", GID: 1001})
		if err != nil || exitCode != 0 {
			t.Fatalf("Execute() exitCode=%d err=%v output=%q", exitCode, err, output)
		}
		if mock.Invoked("/usr/sbin/addgroup") {
			t.Error("addgroup must be skipped when the group already exists with matching gid")
		}
		if !strings.Contains(output, "already exists with GID 1001") {
			t.Errorf("expected an 'already exists' message, got: %q", output)
		}
	})

	t.Run("exists with different gid -> conflict surfaced", func(t *testing.T) {
		originalPlatformLike := utils.PlatformLike
		utils.SetPlatformLike("debian")
		t.Cleanup(func() { utils.SetPlatformLike(originalPlatformLike) })

		mock := common.NewMockCommandExecutor(t)
		handler := newTestGroupHandler(mock)
		handler.lookupGroup = common.ExistingGroupLookup("9999")

		exitCode, output, _ := handler.Execute(context.Background(), "addgroup", &common.CommandArgs{Groupname: "testgroup", GID: 1001})
		if exitCode == 0 {
			t.Fatalf("expected non-zero exit for gid conflict, got 0 (output=%q)", output)
		}
		if !strings.Contains(output, "already exists with gid 9999") || !strings.Contains(output, "requested gid 1001") {
			t.Errorf("conflict message must name both gids, got: %q", output)
		}
		if mock.Invoked("/usr/sbin/addgroup") {
			t.Error("addgroup must not run on a gid conflict")
		}
	})

	t.Run("lookup error -> fail loud, no create", func(t *testing.T) {
		originalPlatformLike := utils.PlatformLike
		utils.SetPlatformLike("debian")
		t.Cleanup(func() { utils.SetPlatformLike(originalPlatformLike) })

		mock := common.NewMockCommandExecutor(t)
		handler := newTestGroupHandler(mock)
		handler.lookupGroup = func(string) (*user.Group, error) {
			return nil, errors.New("getgrnam_r: I/O error")
		}

		exitCode, output, _ := handler.Execute(context.Background(), "addgroup", &common.CommandArgs{Groupname: "testgroup", GID: 1001})
		if exitCode == 0 {
			t.Fatalf("expected non-zero exit when the lookup itself fails, got 0 (output=%q)", output)
		}
		if !strings.Contains(output, "unable to verify") {
			t.Errorf("expected an 'unable to verify' message, got: %q", output)
		}
		if mock.Invoked("/usr/sbin/addgroup") {
			t.Error("addgroup must not run when existence cannot be verified")
		}
	})
}

// TestGroupHandler_AddGroup_SecondaryNet verifies the create-time reconcile:
// absent at the gate, create fails, then a re-verify (plus an "already exists"
// tertiary fallback for NSS-backed groups / gid-in-use collisions the pure-Go
// resolver cannot see) decides the outcome.
func TestGroupHandler_AddGroup_SecondaryNet(t *testing.T) {
	const createCmd = "/usr/sbin/addgroup --gid 1001 testgroup"

	tests := []struct {
		name         string
		createOutput string
		reverifyGID  string
		reverifyErr  error
		wantExitZero bool
		wantMsgPart  string
	}{
		{name: "raced local create, matching gid -> success", createOutput: "addgroup: group already exists", reverifyGID: "1001", wantExitZero: true, wantMsgPart: "already exists"},
		{name: "raced local create, different gid -> conflict", createOutput: "addgroup: group already exists", reverifyGID: "2002", wantExitZero: false, wantMsgPart: "already exists with gid 2002"},
		{name: "NSS-backed same name, absent at reverify but create names this group -> tolerated", createOutput: "addgroup: group 'testgroup' already exists", reverifyErr: user.UnknownGroupError("absent"), wantExitZero: true, wantMsgPart: "already exists"},
		{name: "gid-in-use by a different name, absent at reverify -> surfaced (not masked)", createOutput: "groupadd: GID '1001' already exists", reverifyErr: user.UnknownGroupError("absent"), wantExitZero: false, wantMsgPart: "GID '1001'"},
		{name: "genuine failure, absent and not already-exists -> surfaced", createOutput: "addgroup: cannot open /etc/group", reverifyErr: user.UnknownGroupError("absent"), wantExitZero: false, wantMsgPart: "cannot open"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			originalPlatformLike := utils.PlatformLike
			utils.SetPlatformLike("debian")
			t.Cleanup(func() { utils.SetPlatformLike(originalPlatformLike) })

			mock := common.NewMockCommandExecutor(t)
			mock.SetResult(createCmd, 1, tt.createOutput, errors.New("exit status 1"))
			handler := newTestGroupHandler(mock)

			calls := 0
			handler.lookupGroup = func(name string) (*user.Group, error) {
				calls++
				if calls == 1 {
					return nil, user.UnknownGroupError("absent") // gate: absent -> create attempted
				}
				if tt.reverifyErr != nil {
					return nil, tt.reverifyErr
				}
				return &user.Group{Name: name, Gid: tt.reverifyGID}, nil
			}

			exitCode, output, _ := handler.Execute(context.Background(), "addgroup", &common.CommandArgs{Groupname: "testgroup", GID: 1001})
			if !mock.Invoked("/usr/sbin/addgroup") {
				t.Fatal("addgroup should have been attempted after an absent gate lookup")
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
