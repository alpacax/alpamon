package executor

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/alpacax/alpamon/internal/pool"
	"github.com/alpacax/alpamon/pkg/agent"
	"github.com/alpacax/alpamon/pkg/executor/handlers/common"
)

// IntegrationMockHandler is a more complete mock handler for integration testing
type IntegrationMockHandler struct {
	name           string
	commands       []string
	executeCount   int
	validateCount  int
	executionDelay time.Duration
	mu             sync.Mutex
}

func (h *IntegrationMockHandler) Name() string {
	return h.name
}

func (h *IntegrationMockHandler) Commands() []string {
	return h.commands
}

func (h *IntegrationMockHandler) Execute(ctx context.Context, cmd string, args *common.CommandArgs) (int, string, error) {
	h.mu.Lock()
	h.executeCount++
	h.mu.Unlock()

	if h.executionDelay > 0 {
		select {
		case <-ctx.Done():
			return 1, "", ctx.Err()
		case <-time.After(h.executionDelay):
		}
	}

	return 0, "executed: " + cmd, nil
}

func (h *IntegrationMockHandler) Validate(cmd string, args *common.CommandArgs) error {
	h.mu.Lock()
	h.validateCount++
	h.mu.Unlock()
	return nil
}

func (h *IntegrationMockHandler) GetExecuteCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.executeCount
}

func (h *IntegrationMockHandler) GetValidateCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.validateCount
}

// TestIntegration_RegistryWithHandlers tests that handlers can be registered and retrieved
func TestIntegration_RegistryWithHandlers(t *testing.T) {
	registry := NewRegistry()

	handler1 := &IntegrationMockHandler{
		name:     "handler1",
		commands: []string{"cmd1", "cmd2"},
	}
	handler2 := &IntegrationMockHandler{
		name:     "handler2",
		commands: []string{"cmd3", "cmd4"},
	}

	// Register handlers
	if err := registry.Register(handler1); err != nil {
		t.Fatalf("failed to register handler1: %v", err)
	}
	if err := registry.Register(handler2); err != nil {
		t.Fatalf("failed to register handler2: %v", err)
	}

	// Verify all commands are accessible
	for _, cmd := range []string{"cmd1", "cmd2", "cmd3", "cmd4"} {
		if !registry.IsCommandRegistered(cmd) {
			t.Errorf("command %q should be registered", cmd)
		}
	}

	// Get handlers and verify names
	h1, err := registry.Get("cmd1")
	if err != nil {
		t.Fatalf("failed to get handler for cmd1: %v", err)
	}
	if h1.Name() != "handler1" {
		t.Errorf("expected handler1, got %q", h1.Name())
	}

	h2, err := registry.Get("cmd3")
	if err != nil {
		t.Fatalf("failed to get handler for cmd3: %v", err)
	}
	if h2.Name() != "handler2" {
		t.Errorf("expected handler2, got %q", h2.Name())
	}
}

// TestIntegration_HandlerExecution tests handler execution through registry
func TestIntegration_HandlerExecution(t *testing.T) {
	registry := NewRegistry()

	handler := &IntegrationMockHandler{
		name:     "test_handler",
		commands: []string{"test_cmd"},
	}
	_ = registry.Register(handler)

	// Get handler and execute
	h, err := registry.Get("test_cmd")
	if err != nil {
		t.Fatalf("failed to get handler: %v", err)
	}

	ctx := context.Background()
	args := &common.CommandArgs{}

	// Validate first
	if err := h.Validate("test_cmd", args); err != nil {
		t.Fatalf("validation failed: %v", err)
	}

	// Execute
	exitCode, output, err := h.Execute(ctx, "test_cmd", args)
	if err != nil {
		t.Fatalf("execution failed: %v", err)
	}
	if exitCode != 0 {
		t.Errorf("expected exit code 0, got %d", exitCode)
	}
	if output == "" {
		t.Error("expected non-empty output")
	}

	// Verify counts
	if handler.GetExecuteCount() != 1 {
		t.Errorf("expected execute count 1, got %d", handler.GetExecuteCount())
	}
	if handler.GetValidateCount() != 1 {
		t.Errorf("expected validate count 1, got %d", handler.GetValidateCount())
	}
}

// TestIntegration_ContextCancellation tests that context cancellation is propagated
func TestIntegration_ContextCancellation(t *testing.T) {
	registry := NewRegistry()

	handler := &IntegrationMockHandler{
		name:           "slow_handler",
		commands:       []string{"slow_cmd"},
		executionDelay: 2 * time.Second,
	}
	_ = registry.Register(handler)

	h, _ := registry.Get("slow_cmd")

	// Create context with short timeout
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	args := &common.CommandArgs{}

	// Execute - should timeout
	exitCode, _, err := h.Execute(ctx, "slow_cmd", args)

	if err == nil {
		t.Error("expected context cancellation error")
	}
	if exitCode != 1 {
		t.Errorf("expected exit code 1 on cancellation, got %d", exitCode)
	}
}

// TestIntegration_ConcurrentExecution tests concurrent handler execution
func TestIntegration_ConcurrentExecution(t *testing.T) {
	registry := NewRegistry()

	handler := &IntegrationMockHandler{
		name:           "concurrent_handler",
		commands:       []string{"concurrent_cmd"},
		executionDelay: 10 * time.Millisecond,
	}
	_ = registry.Register(handler)

	h, _ := registry.Get("concurrent_cmd")
	ctx := context.Background()
	args := &common.CommandArgs{}

	var wg sync.WaitGroup
	concurrency := 50

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _, _ = h.Execute(ctx, "concurrent_cmd", args)
		}()
	}

	wg.Wait()

	if handler.GetExecuteCount() != concurrency {
		t.Errorf("expected %d executions, got %d", concurrency, handler.GetExecuteCount())
	}
}

// TestIntegration_PoolWithRegistry tests pool integration with registry
func TestIntegration_PoolWithRegistry(t *testing.T) {
	workerPool := pool.NewPool(5, 100)
	defer workerPool.Shutdown(5 * time.Second)

	ctxManager := agent.NewContextManager()
	defer ctxManager.Shutdown()

	registry := NewRegistry()

	handler := &IntegrationMockHandler{
		name:     "pool_handler",
		commands: []string{"pool_cmd"},
	}
	_ = registry.Register(handler)

	h, _ := registry.Get("pool_cmd")
	args := &common.CommandArgs{}

	var wg sync.WaitGroup
	taskCount := 20

	for i := 0; i < taskCount; i++ {
		wg.Add(1)
		ctx, cancel := ctxManager.NewContext(5 * time.Second)

		err := workerPool.Submit(ctx, func() error {
			defer wg.Done()
			defer cancel()
			_, _, _ = h.Execute(ctx, "pool_cmd", args)
			return nil
		})
		if err != nil {
			wg.Done()
			cancel()
			t.Logf("failed to submit task: %v", err)
		}
	}

	wg.Wait()

	// Allow for some tasks to fail due to pool dynamics
	if handler.GetExecuteCount() < taskCount/2 {
		t.Errorf("expected at least %d executions, got %d", taskCount/2, handler.GetExecuteCount())
	}
}

// TestIntegration_UnregisterHandler tests handler unregistration
func TestIntegration_UnregisterHandler(t *testing.T) {
	registry := NewRegistry()

	handler := &IntegrationMockHandler{
		name:     "removable",
		commands: []string{"remove_cmd"},
	}
	_ = registry.Register(handler)

	// Verify registered
	if !registry.IsCommandRegistered("remove_cmd") {
		t.Error("command should be registered")
	}

	// Unregister
	if err := registry.Unregister("removable"); err != nil {
		t.Fatalf("failed to unregister: %v", err)
	}

	// Verify unregistered
	if registry.IsCommandRegistered("remove_cmd") {
		t.Error("command should not be registered after unregister")
	}
}
