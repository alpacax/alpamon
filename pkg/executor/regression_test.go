package executor

import (
	"testing"
	"time"

	"github.com/alpacax/alpamon/v2/pkg/executor/handlers/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRegression_AllHandlerTypes verifies all expected handler types are available
func TestRegression_AllHandlerTypes(t *testing.T) {
	expectedTypes := []common.HandlerType{
		common.System,
		common.User,
		common.Group,
		common.Firewall,
		common.FileTransfer,
		common.Shell,
		common.Terminal,
		common.Info,
	}

	for _, handlerType := range expectedTypes {
		assert.NotEmpty(t, handlerType.String(), "handler type %v has empty string representation", handlerType)
	}
}

// TestRegression_AllCommandTypes verifies all expected command types are available
func TestRegression_AllCommandTypes(t *testing.T) {
	expectedCommands := []common.CommandType{
		// System commands
		common.Upgrade,
		common.Restart,
		common.Quit,
		common.Reboot,
		common.Shutdown,
		common.Update,
		common.ByeBye,

		// User commands
		common.AddUser,
		common.DelUser,
		common.ModUser,

		// Group commands
		common.AddGroup,
		common.DelGroup,

		// Firewall commands
		common.FirewallCmd,
		common.FirewallRollback,

		// File commands
		common.Upload,
		common.Download,

		// Shell commands
		common.ShellCmd,
		common.Exec,

		// Terminal commands
		common.OpenPty,
		common.OpenFtp,
		common.ResizePty,

		// Info commands
		common.Ping,
		common.Help,
		common.Commit,
		common.Sync,
	}

	for _, cmd := range expectedCommands {
		assert.NotEmpty(t, cmd.String(), "command type %v has empty string representation", cmd)
	}
}

// TestRegression_RegistryOperations verifies registry basic operations work
func TestRegression_RegistryOperations(t *testing.T) {
	registry := NewRegistry()

	// Test empty registry
	assert.Empty(t, registry.List(), "new registry should be empty")

	// Test registration
	handler := &MockHandler{
		name:     "test",
		commands: []string{"cmd1", "cmd2"},
	}

	err := registry.Register(handler)
	require.NoError(t, err, "registration failed")

	// Test listing
	assert.Len(t, registry.List(), 1, "should have 1 handler after registration")

	// Test command check
	assert.True(t, registry.IsCommandRegistered("cmd1"), "cmd1 should be registered")

	// Test get
	h, err := registry.Get("cmd1")
	require.NoError(t, err, "get failed")
	assert.Equal(t, "test", h.Name(), "expected handler name 'test'")

	// Test unregister
	err = registry.Unregister("test")
	require.NoError(t, err, "unregister failed")

	assert.False(t, registry.IsCommandRegistered("cmd1"), "cmd1 should not be registered after unregister")

	// Test clear
	_ = registry.Register(handler)
	registry.Clear()
	assert.Empty(t, registry.List(), "registry should be empty after clear")
}

// TestRegression_CommandArgsFields verifies all CommandArgs fields exist
func TestRegression_CommandArgsFields(t *testing.T) {
	args := &common.CommandArgs{
		// User/Group management
		Username:  "test",
		Groupname: "test",
		Shell:     "/bin/bash",
		UID:       1000,
		GID:       1000,

		// Shell execution
		Command: "ls",
		Env:     map[string]string{"KEY": "VALUE"},
		Timeout: 30 * time.Second,

		// Firewall
		Rules: []common.FirewallRule{},

		// File transfer
		Path: "/test/path",
		URL:  "http://example.com",

		// Terminal
		SessionID: "session-123",
		Rows:      24,
		Cols:      80,

		// System
		Target: "alpamon",

		// Info
		Keys: []string{"cpu", "memory"},
	}

	// Verify all fields are accessible
	assert.NotEmpty(t, args.Username, "Username field not accessible")
	assert.NotEmpty(t, args.Groupname, "Groupname field not accessible")
	assert.NotEmpty(t, args.Shell, "Shell field not accessible")
	assert.NotZero(t, args.UID, "UID field not accessible")
	assert.NotZero(t, args.GID, "GID field not accessible")
	assert.NotEmpty(t, args.Command, "Command field not accessible")
	assert.NotNil(t, args.Env, "Env field not accessible")
	assert.NotZero(t, args.Timeout, "Timeout field not accessible")
	assert.NotNil(t, args.Rules, "Rules field not accessible")
	assert.NotEmpty(t, args.Path, "Path field not accessible")
	assert.NotEmpty(t, args.URL, "URL field not accessible")
	assert.NotEmpty(t, args.SessionID, "SessionID field not accessible")
	assert.NotZero(t, args.Rows, "Rows field not accessible")
	assert.NotZero(t, args.Cols, "Cols field not accessible")
	assert.NotEmpty(t, args.Target, "Target field not accessible")
	assert.NotEmpty(t, args.Keys, "Keys field not accessible")
}

// TestRegression_HandlerInterface verifies Handler interface contract
func TestRegression_HandlerInterface(t *testing.T) {
	var _ common.Handler = (*MockHandler)(nil)

	handler := &MockHandler{
		name:     "test",
		commands: []string{"cmd1"},
	}

	// Name() should return non-empty string
	assert.NotEmpty(t, handler.Name(), "Name() should not return empty string")

	// Commands() should return non-empty slice
	assert.NotEmpty(t, handler.Commands(), "Commands() should not return empty slice")
}

// TestRegression_CommandExecutorInterface verifies CommandExecutor interface exists
func TestRegression_CommandExecutorInterface(t *testing.T) {
	// Verify MockCommandExecutor implements CommandExecutor
	mockExec := common.NewMockCommandExecutor(t)

	var _ common.CommandExecutor = mockExec

	// Test all methods exist
	mockExec.SetResult("test", 0, "output", nil)
	cmds := mockExec.GetExecutedCommands()
	assert.NotNil(t, cmds, "GetExecutedCommands should not return nil")
}

// TestRegression_FirewallRule verifies FirewallRule structure
func TestRegression_FirewallRule(t *testing.T) {
	rule := common.FirewallRule{
		ChainName:   "INPUT",
		Method:      "append",
		Chain:       "INPUT",
		Protocol:    "tcp",
		PortStart:   22,
		PortEnd:     22,
		Source:      "0.0.0.0/0",
		Destination: "0.0.0.0/0",
		Target:      "ACCEPT",
		Description: "Allow SSH",
		Priority:    0,
		RuleType:    "port",
		RuleID:      "rule-1",
	}

	assert.NotEmpty(t, rule.ChainName, "ChainName field not accessible")
	assert.NotEmpty(t, rule.Method, "Method field not accessible")
	assert.NotEmpty(t, rule.Chain, "Chain field not accessible")
	assert.NotEmpty(t, rule.Protocol, "Protocol field not accessible")
	assert.NotZero(t, rule.PortStart, "PortStart field not accessible")
	assert.NotZero(t, rule.PortEnd, "PortEnd field not accessible")
	assert.NotEmpty(t, rule.Source, "Source field not accessible")
	assert.NotEmpty(t, rule.Destination, "Destination field not accessible")
	assert.NotEmpty(t, rule.Target, "Target field not accessible")
	assert.NotEmpty(t, rule.Description, "Description field not accessible")
	assert.NotEmpty(t, rule.RuleType, "RuleType field not accessible")
	assert.NotEmpty(t, rule.RuleID, "RuleID field not accessible")
}
