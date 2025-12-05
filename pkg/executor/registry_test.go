package executor

import (
	"context"
	"testing"

	"github.com/alpacax/alpamon/pkg/executor/handlers/common"
)

// MockHandler is a mock implementation of Handler interface for testing
type MockHandler struct {
	name     string
	commands []string
}

func (h *MockHandler) Name() string {
	return h.name
}

func (h *MockHandler) Commands() []string {
	return h.commands
}

func (h *MockHandler) Execute(ctx context.Context, cmd string, args *common.CommandArgs) (int, string, error) {
	return 0, "mock execution", nil
}

func (h *MockHandler) Validate(cmd string, args *common.CommandArgs) error {
	return nil
}

func TestRegistry_Register(t *testing.T) {
	registry := NewRegistry()

	handler := &MockHandler{
		name:     "test",
		commands: []string{"cmd1", "cmd2"},
	}

	// Test successful registration
	err := registry.Register(handler)
	if err != nil {
		t.Fatalf("Failed to register handler: %v", err)
	}

	// Test duplicate handler registration
	err = registry.Register(handler)
	if err == nil {
		t.Error("Expected error for duplicate handler registration")
	}

	// Test duplicate command registration
	handler2 := &MockHandler{
		name:     "test2",
		commands: []string{"cmd1"}, // cmd1 is already registered
	}
	err = registry.Register(handler2)
	if err == nil {
		t.Error("Expected error for duplicate command registration")
	}
}

func TestRegistry_Get(t *testing.T) {
	registry := NewRegistry()

	handler := &MockHandler{
		name:     "test",
		commands: []string{"cmd1", "cmd2"},
	}

	_ = registry.Register(handler)

	// Test getting existing command
	h, err := registry.Get("cmd1")
	if err != nil {
		t.Fatalf("Failed to get handler for cmd1: %v", err)
	}
	if h.Name() != "test" {
		t.Errorf("Expected handler name 'test', got '%s'", h.Name())
	}

	// Test getting non-existent command
	_, err = registry.Get("nonexistent")
	if err == nil {
		t.Error("Expected error for non-existent command")
	}
}

func TestRegistry_GetHandler(t *testing.T) {
	registry := NewRegistry()

	handler := &MockHandler{
		name:     "test",
		commands: []string{"cmd1", "cmd2"},
	}

	_ = registry.Register(handler)

	// Test getting existing handler
	h, err := registry.GetHandler("test")
	if err != nil {
		t.Fatalf("Failed to get handler 'test': %v", err)
	}
	if h.Name() != "test" {
		t.Errorf("Expected handler name 'test', got '%s'", h.Name())
	}

	// Test getting non-existent handler
	_, err = registry.GetHandler("nonexistent")
	if err == nil {
		t.Error("Expected error for non-existent handler")
	}
}

func TestRegistry_List(t *testing.T) {
	registry := NewRegistry()

	handler1 := &MockHandler{
		name:     "handler1",
		commands: []string{"cmd1"},
	}
	handler2 := &MockHandler{
		name:     "handler2",
		commands: []string{"cmd2"},
	}

	_ = registry.Register(handler1)
	_ = registry.Register(handler2)

	handlers := registry.List()
	if len(handlers) != 2 {
		t.Errorf("Expected 2 handlers, got %d", len(handlers))
	}

	// Check that both handlers are in the list
	foundHandler1 := false
	foundHandler2 := false
	for _, name := range handlers {
		if name == "handler1" {
			foundHandler1 = true
		}
		if name == "handler2" {
			foundHandler2 = true
		}
	}
	if !foundHandler1 || !foundHandler2 {
		t.Error("Not all handlers found in list")
	}
}

func TestRegistry_ListCommands(t *testing.T) {
	registry := NewRegistry()

	handler := &MockHandler{
		name:     "test",
		commands: []string{"cmd1", "cmd2", "cmd3"},
	}

	registry.Register(handler)

	commands := registry.ListCommands()
	if len(commands) != 3 {
		t.Errorf("Expected 3 commands, got %d", len(commands))
	}

	// Check that all commands are in the list
	commandMap := make(map[string]bool)
	for _, cmd := range commands {
		commandMap[cmd] = true
	}
	for _, expected := range []string{"cmd1", "cmd2", "cmd3"} {
		if !commandMap[expected] {
			t.Errorf("Command %s not found in list", expected)
		}
	}
}

func TestRegistry_IsCommandRegistered(t *testing.T) {
	registry := NewRegistry()

	handler := &MockHandler{
		name:     "test",
		commands: []string{"cmd1", "cmd2"},
	}

	registry.Register(handler)

	if !registry.IsCommandRegistered("cmd1") {
		t.Error("Expected cmd1 to be registered")
	}
	if !registry.IsCommandRegistered("cmd2") {
		t.Error("Expected cmd2 to be registered")
	}
	if registry.IsCommandRegistered("nonexistent") {
		t.Error("Expected 'nonexistent' to not be registered")
	}
}

func TestRegistry_Unregister(t *testing.T) {
	registry := NewRegistry()

	handler := &MockHandler{
		name:     "test",
		commands: []string{"cmd1", "cmd2"},
	}

	registry.Register(handler)

	// Verify handler is registered
	if !registry.IsCommandRegistered("cmd1") {
		t.Fatal("Handler not registered properly")
	}

	// Unregister handler
	err := registry.Unregister("test")
	if err != nil {
		t.Fatalf("Failed to unregister handler: %v", err)
	}

	// Verify handler is no longer registered
	if registry.IsCommandRegistered("cmd1") {
		t.Error("Command still registered after unregistering handler")
	}

	// Test unregistering non-existent handler
	err = registry.Unregister("nonexistent")
	if err == nil {
		t.Error("Expected error when unregistering non-existent handler")
	}
}

func TestRegistry_Clear(t *testing.T) {
	registry := NewRegistry()

	// Register multiple handlers
	handler1 := &MockHandler{
		name:     "handler1",
		commands: []string{"cmd1"},
	}
	handler2 := &MockHandler{
		name:     "handler2",
		commands: []string{"cmd2"},
	}

	registry.Register(handler1)
	registry.Register(handler2)

	// Verify handlers are registered
	if len(registry.List()) != 2 {
		t.Fatal("Handlers not registered properly")
	}

	// Clear registry
	registry.Clear()

	// Verify registry is empty
	if len(registry.List()) != 0 {
		t.Error("Registry not cleared properly")
	}
	if len(registry.ListCommands()) != 0 {
		t.Error("Commands not cleared properly")
	}
}

func TestRegistry_ThreadSafety(t *testing.T) {
	registry := NewRegistry()

	// Test concurrent registration
	done := make(chan bool, 10)
	for i := 0; i < 10; i++ {
		go func(n int) {
			handler := &MockHandler{
				name:     "handler" + string(rune('A'+n)),
				commands: []string{"cmd" + string(rune('A'+n))},
			}
			registry.Register(handler)
			done <- true
		}(i)
	}

	// Wait for all goroutines to complete
	for i := 0; i < 10; i++ {
		<-done
	}

	// The test passes if there's no race condition or panic
	t.Log("Thread safety test passed")
}