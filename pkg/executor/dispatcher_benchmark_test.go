package executor

import (
	"context"
	"testing"

	"github.com/alpacax/alpamon/pkg/executor/handlers/common"
)

// BenchmarkRegistry_Get measures registry lookup performance
func BenchmarkRegistry_Get(b *testing.B) {
	registry := NewRegistry()

	// Register a mock handler
	handler := &MockHandler{
		name:     "test",
		commands: []string{"cmd1", "cmd2", "cmd3"},
	}
	_ = registry.Register(handler)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = registry.Get("cmd1")
	}
}

// BenchmarkRegistry_ListCommands measures command listing performance
func BenchmarkRegistry_ListCommands(b *testing.B) {
	registry := NewRegistry()

	// Register multiple handlers
	for i := 0; i < 10; i++ {
		handler := &MockHandler{
			name:     "handler" + string(rune('A'+i)),
			commands: []string{"cmd" + string(rune('A'+i))},
		}
		_ = registry.Register(handler)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = registry.ListCommands()
	}
}

// BenchmarkRegistry_IsCommandRegistered measures registration check performance
func BenchmarkRegistry_IsCommandRegistered(b *testing.B) {
	registry := NewRegistry()

	handler := &MockHandler{
		name:     "test",
		commands: []string{"cmd1", "cmd2", "cmd3"},
	}
	_ = registry.Register(handler)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = registry.IsCommandRegistered("cmd1")
	}
}

// BenchmarkRegistry_ConcurrentGet measures concurrent lookup performance
func BenchmarkRegistry_ConcurrentGet(b *testing.B) {
	registry := NewRegistry()

	handler := &MockHandler{
		name:     "test",
		commands: []string{"cmd1", "cmd2", "cmd3"},
	}
	_ = registry.Register(handler)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, _ = registry.Get("cmd1")
		}
	})
}

// MockHandlerWithExecute is a handler that can be used for execution benchmarks
type MockHandlerWithExecute struct {
	name     string
	commands []string
}

func (h *MockHandlerWithExecute) Name() string {
	return h.name
}

func (h *MockHandlerWithExecute) Commands() []string {
	return h.commands
}

func (h *MockHandlerWithExecute) Execute(ctx context.Context, cmd string, args *common.CommandArgs) (int, string, error) {
	return 0, "executed", nil
}

func (h *MockHandlerWithExecute) Validate(cmd string, args *common.CommandArgs) error {
	return nil
}

// BenchmarkHandler_Execute measures basic handler execution overhead
func BenchmarkHandler_Execute(b *testing.B) {
	handler := &MockHandlerWithExecute{
		name:     "test",
		commands: []string{"test_cmd"},
	}
	ctx := context.Background()
	args := &common.CommandArgs{}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = handler.Execute(ctx, "test_cmd", args)
	}
}
