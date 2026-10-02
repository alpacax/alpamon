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
	"testing"

	"github.com/alpacax/alpamon/v2/pkg/executor/handlers/common"
	"github.com/alpacax/alpamon/v2/pkg/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
	require.NoError(t, err, "Validation failed")

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
			assert.Equal(t, tc.wantErr, err != nil, "Validate() error = %v", err)
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
	require.NoError(t, err, "Validation failed")

	// Test missing groupname
	emptyArgs := &common.CommandArgs{}
	err = handler.Validate("delgroup", emptyArgs)
	assert.Error(t, err, "Expected error for missing groupname")
}

func TestGroupHandler_Commands(t *testing.T) {
	handler := NewGroupHandler(nil, nil) // NewGroupHandler expects common.CommandExecutor, but for validation only, nil is fine

	commands := handler.Commands()
	expectedCommands := []string{"addgroup", "delgroup"}

	assert.Equal(t, expectedCommands, commands)
}

func TestGroupHandler_Name(t *testing.T) {
	handler := NewGroupHandler(nil, nil) // NewGroupHandler expects common.CommandExecutor, but for validation only, nil is fine

	assert.Equal(t, "group", handler.Name())
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
			require.NoError(t, err, "Execute() exitCode=%d output=%q", exitCode, output)
			require.Equal(t, 0, exitCode, "Execute() output=%q", output)
			assert.True(t, mock.Invoked(tt.createCmd), "expected %s to be invoked; got %+v", tt.createCmd, mock.GetExecutedCommands())
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
		require.NoError(t, err, "Execute() exitCode=%d output=%q", exitCode, output)
		require.Equal(t, 0, exitCode, "Execute() output=%q", output)
		assert.False(t, mock.Invoked("/usr/sbin/addgroup"), "addgroup must be skipped when the group already exists with matching gid")
		assert.Contains(t, output, "already exists with GID 1001", "expected an 'already exists' message")
	})

	t.Run("exists with different gid -> conflict surfaced", func(t *testing.T) {
		originalPlatformLike := utils.PlatformLike
		utils.SetPlatformLike("debian")
		t.Cleanup(func() { utils.SetPlatformLike(originalPlatformLike) })

		mock := common.NewMockCommandExecutor(t)
		handler := newTestGroupHandler(mock)
		handler.lookupGroup = common.ExistingGroupLookup("9999")

		exitCode, output, _ := handler.Execute(context.Background(), "addgroup", &common.CommandArgs{Groupname: "testgroup", GID: 1001})
		require.NotEqual(t, 0, exitCode, "expected non-zero exit for gid conflict (output=%q)", output)
		assert.Contains(t, output, "already exists with gid 9999", "conflict message must name both gids")
		assert.Contains(t, output, "requested gid 1001", "conflict message must name both gids")
		assert.False(t, mock.Invoked("/usr/sbin/addgroup"), "addgroup must not run on a gid conflict")
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
		require.NotEqual(t, 0, exitCode, "expected non-zero exit when the lookup itself fails (output=%q)", output)
		assert.Contains(t, output, "unable to verify", "expected an 'unable to verify' message")
		assert.False(t, mock.Invoked("/usr/sbin/addgroup"), "addgroup must not run when existence cannot be verified")
	})
}

// TestGroupHandler_AddGroup_NumericNameGidCollisionSurfaced guards the tertiary
// net against a numeric group name aliasing a gid-in-use message: when the
// requested name is "1001" and gid 1001 is owned by a DIFFERENT group, groupadd
// prints "GID '1001' already exists" (naming the gid, not "group '1001'"). The
// requested name is never created, so this must be surfaced, not tolerated.
func TestGroupHandler_AddGroup_NumericNameGidCollisionSurfaced(t *testing.T) {
	originalPlatformLike := utils.PlatformLike
	utils.SetPlatformLike("rhel")
	t.Cleanup(func() { utils.SetPlatformLike(originalPlatformLike) })

	mock := common.NewMockCommandExecutor(t)
	mock.SetResult("/usr/sbin/groupadd --gid 1001 1001", 1, "groupadd: GID '1001' already exists", errors.New("exit status 4"))
	handler := newTestGroupHandler(mock) // AbsentGroupLookup: gate + reconcile both see the name as absent

	exitCode, output, _ := handler.Execute(context.Background(), "addgroup", &common.CommandArgs{Groupname: "1001", GID: 1001})
	require.NotEqual(t, 0, exitCode, "a gid-in-use collision by a different group must be surfaced even when the requested name is numeric (output=%q)", output)
	assert.Contains(t, output, "GID '1001'", "expected the original gid-collision failure to surface")
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
			require.True(t, mock.Invoked("/usr/sbin/addgroup"), "addgroup should have been attempted after an absent gate lookup")
			if tt.wantExitZero {
				require.Equal(t, 0, exitCode, "expected idempotent success (exit 0), output=%q", output)
			} else {
				require.NotEqual(t, 0, exitCode, "expected non-zero exit, output=%q", output)
			}
			if tt.wantMsgPart != "" {
				assert.Contains(t, output, tt.wantMsgPart)
			}
		})
	}
}
