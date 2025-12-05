package executor_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/alpacax/alpamon/internal/pool"
	"github.com/alpacax/alpamon/pkg/agent"
	"github.com/alpacax/alpamon/pkg/executor"
	"github.com/alpacax/alpamon/pkg/executor/handlers/info"
	"github.com/alpacax/alpamon/pkg/executor/handlers/group"
	"github.com/alpacax/alpamon/pkg/executor/handlers/shell"
)

// Example demonstrates how to use the new executor
func ExampleCommandDispatcher_Execute() {
	// Create dependencies
	workerPool := pool.NewPool(4, 100)
	ctxManager := agent.NewContextManager()

	// Create command dispatcher
	exec := executor.NewCommandDispatcher(workerPool, ctxManager)

	// Register info handler
	infoHandler := info.NewInfoHandler(nil) // nil for this example
	_ = exec.RegisterHandler(infoHandler)

	// Execute a command
	ctx := context.Background()
	exitCode, _, err := exec.Execute(ctx, "ping", nil)

	if err == nil && exitCode == 0 {
		fmt.Println("Command executed successfully")
		// Output would contain timestamp
	}

	// Output: Command executed successfully
}

func TestExecutorIntegration(t *testing.T) {
	// Create dependencies
	workerPool := pool.NewPool(4, 100)
	defer workerPool.Shutdown(0)

	ctxManager := agent.NewContextManager()
	defer ctxManager.Shutdown()

	// Create command dispatcher
	exec := executor.NewCommandDispatcher(workerPool, ctxManager)

	// Create command executor
	cmdExecutor := executor.NewExecutor()

	// Register handlers
	infoHandler := info.NewInfoHandler(nil)
	if err := exec.RegisterHandler(infoHandler); err != nil {
		t.Fatalf("Failed to register info handler: %v", err)
	}

	groupHandler := group.NewGroupHandler(cmdExecutor, nil)
	if err := exec.RegisterHandler(groupHandler); err != nil {
		t.Fatalf("Failed to register group handler: %v", err)
	}

	shellHandler := shell.NewShellHandler(cmdExecutor)
	if err := exec.RegisterHandler(shellHandler); err != nil {
		t.Fatalf("Failed to register shell handler: %v", err)
	}

	// Test ping command
	ctx := context.Background()
	exitCode, output, err := exec.Execute(ctx, "ping", nil)
	if err != nil {
		t.Errorf("Ping command failed: %v", err)
	}
	if exitCode != 0 {
		t.Errorf("Ping command returned non-zero exit code: %d", exitCode)
	}
	if output == "" {
		t.Error("Ping command returned empty output")
	}

	// Test help command
	exitCode, output, err = exec.Execute(ctx, "help", nil)
	if err != nil {
		t.Errorf("Help command failed: %v", err)
	}
	if exitCode != 0 {
		t.Errorf("Help command returned non-zero exit code: %d", exitCode)
	}
	if output == "" {
		t.Error("Help command returned empty output")
	}

	// Verify supported commands
	commands := exec.GetSupportedCommands()
	expectedCommands := []string{"ping", "help", "commit", "sync", "addgroup", "delgroup", "shell", "exec"}

	commandMap := make(map[string]bool)
	for _, cmd := range commands {
		commandMap[cmd] = true
	}

	for _, expected := range expectedCommands {
		if !commandMap[expected] {
			t.Errorf("Expected command %s not found in supported commands", expected)
		}
	}

	t.Logf("Executor successfully registered %d handlers with %d total commands",
		len(exec.GetHandlers()), len(commands))
}