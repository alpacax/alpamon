package executor

import (
	"context"
	"testing"

	"github.com/alpacax/alpamon/v2/pkg/executor/handlers/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
	require.NoError(t, err, "Failed to register handler")

	// Test duplicate handler registration
	err = registry.Register(handler)
	assert.Error(t, err, "Expected error for duplicate handler registration")

	// Test duplicate command registration
	handler2 := &MockHandler{
		name:     "test2",
		commands: []string{"cmd1"}, // cmd1 is already registered
	}
	err = registry.Register(handler2)
	assert.Error(t, err, "Expected error for duplicate command registration")
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
	require.NoError(t, err, "Failed to get handler for cmd1")
	assert.Equal(t, "test", h.Name(), "Expected handler name 'test'")

	// Test getting non-existent command
	_, err = registry.Get("nonexistent")
	assert.Error(t, err, "Expected error for non-existent command")
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
	require.NoError(t, err, "Failed to get handler 'test'")
	assert.Equal(t, "test", h.Name(), "Expected handler name 'test'")

	// Test getting non-existent handler
	_, err = registry.GetHandler("nonexistent")
	assert.Error(t, err, "Expected error for non-existent handler")
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
	assert.ElementsMatch(t, []string{"handler1", "handler2"}, handlers, "Not all handlers found in list")
}

func TestRegistry_ListCommands(t *testing.T) {
	registry := NewRegistry()

	handler := &MockHandler{
		name:     "test",
		commands: []string{"cmd1", "cmd2", "cmd3"},
	}

	_ = registry.Register(handler)

	commands := registry.ListCommands()
	assert.ElementsMatch(t, []string{"cmd1", "cmd2", "cmd3"}, commands)
}

func TestRegistry_IsCommandRegistered(t *testing.T) {
	registry := NewRegistry()

	handler := &MockHandler{
		name:     "test",
		commands: []string{"cmd1", "cmd2"},
	}

	_ = registry.Register(handler)

	assert.True(t, registry.IsCommandRegistered("cmd1"), "Expected cmd1 to be registered")
	assert.True(t, registry.IsCommandRegistered("cmd2"), "Expected cmd2 to be registered")
	assert.False(t, registry.IsCommandRegistered("nonexistent"), "Expected 'nonexistent' to not be registered")
}

func TestRegistry_Unregister(t *testing.T) {
	registry := NewRegistry()

	handler := &MockHandler{
		name:     "test",
		commands: []string{"cmd1", "cmd2"},
	}

	_ = registry.Register(handler)

	// Verify handler is registered
	require.True(t, registry.IsCommandRegistered("cmd1"), "Handler not registered properly")

	// Unregister handler
	err := registry.Unregister("test")
	require.NoError(t, err, "Failed to unregister handler")

	// Verify handler is no longer registered
	assert.False(t, registry.IsCommandRegistered("cmd1"), "Command still registered after unregistering handler")

	// Test unregistering non-existent handler
	err = registry.Unregister("nonexistent")
	assert.Error(t, err, "Expected error when unregistering non-existent handler")
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

	_ = registry.Register(handler1)
	_ = registry.Register(handler2)

	// Verify handlers are registered
	require.Len(t, registry.List(), 2, "Handlers not registered properly")

	// Clear registry
	registry.Clear()

	// Verify registry is empty
	assert.Empty(t, registry.List(), "Registry not cleared properly")
	assert.Empty(t, registry.ListCommands(), "Commands not cleared properly")
}

func TestRegistry_ThreadSafety(t *testing.T) {
	registry := NewRegistry()

	// Test concurrent registration
	done := make(chan bool, 10)
	for i := range 10 {
		go func(n int) {
			handler := &MockHandler{
				name:     "handler" + string(rune('A'+n)),
				commands: []string{"cmd" + string(rune('A'+n))},
			}
			_ = registry.Register(handler)
			done <- true
		}(i)
	}

	// Wait for all goroutines to complete
	for range 10 {
		<-done
	}

	// The test passes if there's no race condition or panic
	t.Log("Thread safety test passed")
}
