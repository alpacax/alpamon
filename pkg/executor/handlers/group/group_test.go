package group

import (
	"testing"

	"github.com/alpacax/alpamon/pkg/executor/handlers/common"
)

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
