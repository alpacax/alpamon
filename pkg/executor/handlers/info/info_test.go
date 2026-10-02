package info

import (
	"context"
	"testing"
	"testing/synctest"
	"time"

	"github.com/alpacax/alpamon/v2/pkg/executor/handlers/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
	assert.Equal(t, common.Info.String(), handler.Name())
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

	assert.Equal(t, expected, commands)
}

func TestInfoHandler_Ping(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		handler := NewInfoHandler(nil)
		ctx := context.Background()
		args := &common.CommandArgs{}

		exitCode, output, err := handler.Execute(ctx, common.Ping.String(), args)

		require.NoError(t, err)
		assert.Equal(t, 0, exitCode)

		parsedTime, parseErr := time.Parse(time.RFC3339, output)
		require.NoError(t, parseErr, "output is not valid RFC3339 timestamp")

		// RFC3339 keeps whole seconds, so an exact compare needs a clock with no
		// sub-second part. Asserting that beats trusting it: a change to either end
		// then fails with the reason instead of as a puzzling timestamp mismatch.
		now := time.Now()
		require.Equal(t, now.Truncate(time.Second), now, "the bubble's clock must start on a whole second")
		assert.True(t, parsedTime.Equal(now), "timestamp %v is not the current time %v", parsedTime, now)
	})
}

func TestInfoHandler_Help(t *testing.T) {
	handler := NewInfoHandler(nil)
	ctx := context.Background()
	args := &common.CommandArgs{}

	exitCode, output, err := handler.Execute(ctx, common.Help.String(), args)

	require.NoError(t, err)
	assert.Equal(t, 0, exitCode)

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
		assert.Contains(t, output, section, "help message missing section")
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
		assert.Contains(t, output, cmd, "help message missing command")
	}
}

func TestInfoHandler_Commit(t *testing.T) {
	mockManager := &MockSystemInfoManager{}
	handler := NewInfoHandler(mockManager)
	ctx := context.Background()
	args := &common.CommandArgs{}

	exitCode, output, err := handler.Execute(ctx, common.Commit.String(), args)

	require.NoError(t, err)
	assert.Equal(t, 0, exitCode)
	assert.Contains(t, output, "Committed")
	assert.True(t, mockManager.CommitCalled, "expected CommitSystemInfo to be called")
}

func TestInfoHandler_Commit_NilManager(t *testing.T) {
	handler := NewInfoHandler(nil)
	ctx := context.Background()
	args := &common.CommandArgs{}

	// Should not panic with nil manager
	exitCode, output, err := handler.Execute(ctx, common.Commit.String(), args)

	require.NoError(t, err)
	assert.Equal(t, 0, exitCode)
	assert.Contains(t, output, "Committed")
}

func TestInfoHandler_Sync(t *testing.T) {
	mockManager := &MockSystemInfoManager{}
	handler := NewInfoHandler(mockManager)
	ctx := context.Background()
	args := &common.CommandArgs{}

	exitCode, output, err := handler.Execute(ctx, common.Sync.String(), args)

	require.NoError(t, err)
	assert.Equal(t, 0, exitCode)
	assert.Contains(t, output, "Synchronized")
	assert.True(t, mockManager.SyncCalled, "expected SyncSystemInfo to be called")
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

	require.NoError(t, err)
	assert.Equal(t, 0, exitCode)
	assert.Contains(t, output, "Synchronized")
	assert.True(t, mockManager.SyncCalled, "expected SyncSystemInfo to be called")
	assert.Equal(t, keys, mockManager.SyncKeys)
}

func TestInfoHandler_Sync_NilManager(t *testing.T) {
	handler := NewInfoHandler(nil)
	ctx := context.Background()
	args := &common.CommandArgs{
		Keys: []string{"cpu"},
	}

	// Should not panic with nil manager
	exitCode, output, err := handler.Execute(ctx, common.Sync.String(), args)

	require.NoError(t, err)
	assert.Equal(t, 0, exitCode)
	assert.Contains(t, output, "Synchronized")
}

func TestInfoHandler_UnknownCommand(t *testing.T) {
	handler := NewInfoHandler(nil)
	ctx := context.Background()
	args := &common.CommandArgs{}

	exitCode, _, err := handler.Execute(ctx, "unknown_command", args)

	assert.Equal(t, 1, exitCode)
	assert.ErrorContains(t, err, "unknown info command")
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
			assert.NoError(t, err, "unexpected validation error")
		})
	}
}
