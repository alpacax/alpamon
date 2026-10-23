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
