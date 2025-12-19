package executor

import (
	"testing"
	"time"

	"github.com/alpacax/alpamon/pkg/executor/handlers/common"
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
		if handlerType.String() == "" {
			t.Errorf("handler type %v has empty string representation", handlerType)
		}
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
		if cmd.String() == "" {
			t.Errorf("command type %v has empty string representation", cmd)
		}
	}
}

// TestRegression_RegistryOperations verifies registry basic operations work
func TestRegression_RegistryOperations(t *testing.T) {
	registry := NewRegistry()

	// Test empty registry
	if len(registry.List()) != 0 {
		t.Error("new registry should be empty")
	}

	// Test registration
	handler := &MockHandler{
		name:     "test",
		commands: []string{"cmd1", "cmd2"},
	}

	if err := registry.Register(handler); err != nil {
		t.Fatalf("registration failed: %v", err)
	}

	// Test listing
	if len(registry.List()) != 1 {
		t.Error("should have 1 handler after registration")
	}

	// Test command check
	if !registry.IsCommandRegistered("cmd1") {
		t.Error("cmd1 should be registered")
	}

	// Test get
	h, err := registry.Get("cmd1")
	if err != nil {
		t.Fatalf("get failed: %v", err)
	}
	if h.Name() != "test" {
		t.Errorf("expected handler name 'test', got '%s'", h.Name())
	}

	// Test unregister
	if err := registry.Unregister("test"); err != nil {
		t.Fatalf("unregister failed: %v", err)
	}

	if registry.IsCommandRegistered("cmd1") {
		t.Error("cmd1 should not be registered after unregister")
	}

	// Test clear
	_ = registry.Register(handler)
	registry.Clear()
	if len(registry.List()) != 0 {
		t.Error("registry should be empty after clear")
	}
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
	if args.Username == "" {
		t.Error("Username field not accessible")
	}
	if args.Groupname == "" {
		t.Error("Groupname field not accessible")
	}
	if args.Shell == "" {
		t.Error("Shell field not accessible")
	}
	if args.UID == 0 {
		t.Error("UID field not accessible")
	}
	if args.GID == 0 {
		t.Error("GID field not accessible")
	}
	if args.Command == "" {
		t.Error("Command field not accessible")
	}
	if args.Env == nil {
		t.Error("Env field not accessible")
	}
	if args.Timeout == 0 {
		t.Error("Timeout field not accessible")
	}
	if args.Rules == nil {
		t.Error("Rules field not accessible")
	}
	if args.Path == "" {
		t.Error("Path field not accessible")
	}
	if args.URL == "" {
		t.Error("URL field not accessible")
	}
	if args.SessionID == "" {
		t.Error("SessionID field not accessible")
	}
	if args.Rows == 0 {
		t.Error("Rows field not accessible")
	}
	if args.Cols == 0 {
		t.Error("Cols field not accessible")
	}
	if args.Target == "" {
		t.Error("Target field not accessible")
	}
	if len(args.Keys) == 0 {
		t.Error("Keys field not accessible")
	}
}

// TestRegression_HandlerInterface verifies Handler interface contract
func TestRegression_HandlerInterface(t *testing.T) {
	var _ common.Handler = (*MockHandler)(nil)

	handler := &MockHandler{
		name:     "test",
		commands: []string{"cmd1"},
	}

	// Name() should return non-empty string
	if handler.Name() == "" {
		t.Error("Name() should not return empty string")
	}

	// Commands() should return non-empty slice
	if len(handler.Commands()) == 0 {
		t.Error("Commands() should not return empty slice")
	}
}

// TestRegression_CommandExecutorInterface verifies CommandExecutor interface exists
func TestRegression_CommandExecutorInterface(t *testing.T) {
	// Verify MockCommandExecutor implements CommandExecutor
	mockExec := common.NewMockCommandExecutor(t)

	var _ common.CommandExecutor = mockExec

	// Test all methods exist
	mockExec.SetResult("test ", 0, "output", nil)
	cmds := mockExec.GetExecutedCommands()
	if cmds == nil {
		t.Error("GetExecutedCommands should not return nil")
	}
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

	if rule.ChainName == "" {
		t.Error("ChainName field not accessible")
	}
	if rule.Method == "" {
		t.Error("Method field not accessible")
	}
	if rule.Chain == "" {
		t.Error("Chain field not accessible")
	}
	if rule.Protocol == "" {
		t.Error("Protocol field not accessible")
	}
	if rule.PortStart == 0 {
		t.Error("PortStart field not accessible")
	}
	if rule.PortEnd == 0 {
		t.Error("PortEnd field not accessible")
	}
	if rule.Source == "" {
		t.Error("Source field not accessible")
	}
	if rule.Destination == "" {
		t.Error("Destination field not accessible")
	}
	if rule.Target == "" {
		t.Error("Target field not accessible")
	}
	if rule.Description == "" {
		t.Error("Description field not accessible")
	}
	if rule.RuleType == "" {
		t.Error("RuleType field not accessible")
	}
	if rule.RuleID == "" {
		t.Error("RuleID field not accessible")
	}
}
