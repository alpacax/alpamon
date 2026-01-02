package info

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/alpacax/alpamon/pkg/executor/handlers/common"
)

// MockSystemInfoManager is a mock implementation of SystemInfoManager for testing
type MockSystemInfoManager struct {
	CommitCalled bool
	SyncCalled   bool
	SyncKeys     []string
}

func (m *MockSystemInfoManager) CommitSystemInfo() {
	m.CommitCalled = true
}

func (m *MockSystemInfoManager) SyncSystemInfo(keys []string) {
	m.SyncCalled = true
	m.SyncKeys = keys
}

func TestInfoHandler_Name(t *testing.T) {
	handler := NewInfoHandler(nil)
	if handler.Name() != common.Info.String() {
		t.Errorf("expected name %q, got %q", common.Info.String(), handler.Name())
	}
}

func TestInfoHandler_Commands(t *testing.T) {
	handler := NewInfoHandler(nil)
	commands := handler.Commands()

	expected := []string{
		common.Ping.String(),
		common.Help.String(),
		common.Commit.String(),
		common.Sync.String(),
	}

	if len(commands) != len(expected) {
		t.Errorf("expected %d commands, got %d", len(expected), len(commands))
		return
	}

	for i, cmd := range commands {
		if cmd != expected[i] {
			t.Errorf("command %d: expected %q, got %q", i, expected[i], cmd)
		}
	}
}

func TestInfoHandler_Ping(t *testing.T) {
	handler := NewInfoHandler(nil)
	ctx := context.Background()
	args := &common.CommandArgs{}

	before := time.Now().Add(-1 * time.Second) // Allow 1 second tolerance before
	exitCode, output, err := handler.Execute(ctx, common.Ping.String(), args)
	after := time.Now().Add(1 * time.Second) // Allow 1 second tolerance after

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if exitCode != 0 {
		t.Errorf("expected exit code 0, got %d", exitCode)
	}

	// Verify output is RFC3339 timestamp
	parsedTime, parseErr := time.Parse(time.RFC3339, output)
	if parseErr != nil {
		t.Errorf("output is not valid RFC3339 timestamp: %v", parseErr)
	}

	// Verify timestamp is within expected range (with tolerance for RFC3339 second precision)
	if parsedTime.Before(before) || parsedTime.After(after) {
		t.Errorf("timestamp %v not within expected range [%v, %v]", parsedTime, before, after)
	}
}

func TestInfoHandler_Help(t *testing.T) {
	handler := NewInfoHandler(nil)
	ctx := context.Background()
	args := &common.CommandArgs{}

	exitCode, output, err := handler.Execute(ctx, common.Help.String(), args)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if exitCode != 0 {
		t.Errorf("expected exit code 0, got %d", exitCode)
	}

	// Verify help message contains expected sections
	expectedSections := []string{
		"Available commands",
		"System Control:",
		"User Management:",
		"Group Management:",
		"Firewall Management:",
		"File Operations:",
		"Terminal Operations:",
		"System Information:",
		"Package Management:",
		"Shell Commands:",
	}

	for _, section := range expectedSections {
		if !strings.Contains(output, section) {
			t.Errorf("help message missing section: %q", section)
		}
	}

	// Verify key commands are documented
	expectedCommands := []string{
		"upgrade", "restart", "quit", "reboot", "shutdown",
		"adduser", "deluser", "moduser",
		"addgroup", "delgroup",
		"firewall", "upload", "download",
		"openpty", "openftp",
		"commit", "sync", "ping", "help",
	}

	for _, cmd := range expectedCommands {
		if !strings.Contains(output, cmd) {
			t.Errorf("help message missing command: %q", cmd)
		}
	}
}

func TestInfoHandler_Commit(t *testing.T) {
	mockManager := &MockSystemInfoManager{}
	handler := NewInfoHandler(mockManager)
	ctx := context.Background()
	args := &common.CommandArgs{}

	exitCode, output, err := handler.Execute(ctx, common.Commit.String(), args)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if exitCode != 0 {
		t.Errorf("expected exit code 0, got %d", exitCode)
	}
	if !strings.Contains(output, "Committed") {
		t.Errorf("expected output to contain 'Committed', got %q", output)
	}
	if !mockManager.CommitCalled {
		t.Error("expected CommitSystemInfo to be called")
	}
}

func TestInfoHandler_Commit_NilManager(t *testing.T) {
	handler := NewInfoHandler(nil)
	ctx := context.Background()
	args := &common.CommandArgs{}

	// Should not panic with nil manager
	exitCode, output, err := handler.Execute(ctx, common.Commit.String(), args)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if exitCode != 0 {
		t.Errorf("expected exit code 0, got %d", exitCode)
	}
	if !strings.Contains(output, "Committed") {
		t.Errorf("expected output to contain 'Committed', got %q", output)
	}
}

func TestInfoHandler_Sync(t *testing.T) {
	mockManager := &MockSystemInfoManager{}
	handler := NewInfoHandler(mockManager)
	ctx := context.Background()
	args := &common.CommandArgs{}

	exitCode, output, err := handler.Execute(ctx, common.Sync.String(), args)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if exitCode != 0 {
		t.Errorf("expected exit code 0, got %d", exitCode)
	}
	if !strings.Contains(output, "Synchronized") {
		t.Errorf("expected output to contain 'Synchronized', got %q", output)
	}
	if !mockManager.SyncCalled {
		t.Error("expected SyncSystemInfo to be called")
	}
}

func TestInfoHandler_Sync_WithKeys(t *testing.T) {
	mockManager := &MockSystemInfoManager{}
	handler := NewInfoHandler(mockManager)
	ctx := context.Background()
	keys := []string{"cpu", "memory", "disk"}
	args := &common.CommandArgs{
		Keys: keys,
	}

	exitCode, output, err := handler.Execute(ctx, common.Sync.String(), args)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if exitCode != 0 {
		t.Errorf("expected exit code 0, got %d", exitCode)
	}
	if !strings.Contains(output, "Synchronized") {
		t.Errorf("expected output to contain 'Synchronized', got %q", output)
	}
	if !mockManager.SyncCalled {
		t.Error("expected SyncSystemInfo to be called")
	}
	if len(mockManager.SyncKeys) != len(keys) {
		t.Errorf("expected %d keys, got %d", len(keys), len(mockManager.SyncKeys))
	}
	for i, key := range keys {
		if mockManager.SyncKeys[i] != key {
			t.Errorf("key %d: expected %q, got %q", i, key, mockManager.SyncKeys[i])
		}
	}
}

func TestInfoHandler_Sync_NilManager(t *testing.T) {
	handler := NewInfoHandler(nil)
	ctx := context.Background()
	args := &common.CommandArgs{
		Keys: []string{"cpu"},
	}

	// Should not panic with nil manager
	exitCode, output, err := handler.Execute(ctx, common.Sync.String(), args)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if exitCode != 0 {
		t.Errorf("expected exit code 0, got %d", exitCode)
	}
	if !strings.Contains(output, "Synchronized") {
		t.Errorf("expected output to contain 'Synchronized', got %q", output)
	}
}

func TestInfoHandler_UnknownCommand(t *testing.T) {
	handler := NewInfoHandler(nil)
	ctx := context.Background()
	args := &common.CommandArgs{}

	exitCode, _, err := handler.Execute(ctx, "unknown_command", args)

	if err == nil {
		t.Error("expected error for unknown command")
	}
	if exitCode != 1 {
		t.Errorf("expected exit code 1, got %d", exitCode)
	}
	if !strings.Contains(err.Error(), "unknown info command") {
		t.Errorf("error should mention 'unknown info command', got: %v", err)
	}
}

func TestInfoHandler_Validate(t *testing.T) {
	handler := NewInfoHandler(nil)

	testCases := []struct {
		name string
		cmd  string
		args *common.CommandArgs
	}{
		{"ping", common.Ping.String(), &common.CommandArgs{}},
		{"help", common.Help.String(), &common.CommandArgs{}},
		{"commit", common.Commit.String(), &common.CommandArgs{}},
		{"sync without keys", common.Sync.String(), &common.CommandArgs{}},
		{"sync with keys", common.Sync.String(), &common.CommandArgs{Keys: []string{"cpu", "memory"}}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := handler.Validate(tc.cmd, tc.args)
			if err != nil {
				t.Errorf("unexpected validation error: %v", err)
			}
		})
	}
}
