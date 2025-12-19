package system

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/alpacax/alpamon/internal/pool"
	"github.com/alpacax/alpamon/pkg/agent"
	"github.com/alpacax/alpamon/pkg/executor/handlers/common"
)

// MockWSClient is a mock implementation of WSClient for testing
type MockWSClient struct {
	RestartCalled          bool
	ShutDownCalled         bool
	RestartCollectorCalled bool
}

func (m *MockWSClient) Restart() {
	m.RestartCalled = true
}

func (m *MockWSClient) ShutDown() {
	m.ShutDownCalled = true
}

func (m *MockWSClient) RestartCollector() {
	m.RestartCollectorCalled = true
}

func TestSystemHandler_Name(t *testing.T) {
	mockExec := common.NewMockCommandExecutor(t)
	mockWS := &MockWSClient{}
	ctxManager := agent.NewContextManager()
	workerPool := pool.NewPool(2, 10)
	defer func() { _ = workerPool.Shutdown(1 * time.Second) }()
	defer ctxManager.Shutdown()

	handler := NewSystemHandler(mockExec, mockWS, ctxManager, workerPool)
	if handler.Name() != common.System.String() {
		t.Errorf("expected name %q, got %q", common.System.String(), handler.Name())
	}
}

func TestSystemHandler_Commands(t *testing.T) {
	mockExec := common.NewMockCommandExecutor(t)
	mockWS := &MockWSClient{}
	ctxManager := agent.NewContextManager()
	workerPool := pool.NewPool(2, 10)
	defer func() { _ = workerPool.Shutdown(1 * time.Second) }()
	defer ctxManager.Shutdown()

	handler := NewSystemHandler(mockExec, mockWS, ctxManager, workerPool)
	commands := handler.Commands()

	expected := []string{
		common.Upgrade.String(),
		common.Restart.String(),
		common.Quit.String(),
		common.Reboot.String(),
		common.Shutdown.String(),
		common.Update.String(),
		common.ByeBye.String(),
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

func TestSystemHandler_Restart_Collector(t *testing.T) {
	mockExec := common.NewMockCommandExecutor(t)
	mockWS := &MockWSClient{}
	ctxManager := agent.NewContextManager()
	workerPool := pool.NewPool(2, 10)
	defer func() { _ = workerPool.Shutdown(1 * time.Second) }()
	defer ctxManager.Shutdown()

	handler := NewSystemHandler(mockExec, mockWS, ctxManager, workerPool)
	ctx := context.Background()

	args := &common.CommandArgs{
		Target: "collector",
	}

	exitCode, output, err := handler.Execute(ctx, common.Restart.String(), args)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if exitCode != 0 {
		t.Errorf("expected exit code 0, got %d", exitCode)
	}
	if !mockWS.RestartCollectorCalled {
		t.Error("expected RestartCollector to be called")
	}
	if !strings.Contains(output, "restarted") {
		t.Errorf("expected output to contain 'restarted', got %q", output)
	}
}

func TestSystemHandler_Restart_Default(t *testing.T) {
	mockExec := common.NewMockCommandExecutor(t)
	mockWS := &MockWSClient{}
	ctxManager := agent.NewContextManager()
	workerPool := pool.NewPool(2, 10)
	defer func() { _ = workerPool.Shutdown(1 * time.Second) }()
	defer ctxManager.Shutdown()

	handler := NewSystemHandler(mockExec, mockWS, ctxManager, workerPool)
	ctx := context.Background()

	args := &common.CommandArgs{
		// No target - should default to alpamon
	}

	exitCode, output, err := handler.Execute(ctx, common.Restart.String(), args)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if exitCode != 0 {
		t.Errorf("expected exit code 0, got %d", exitCode)
	}
	if !strings.Contains(output, "restart") {
		t.Errorf("expected output to mention restart, got %q", output)
	}
	// Give time for the pool task to execute
	time.Sleep(100 * time.Millisecond)
}

func TestSystemHandler_Restart_Alpamon(t *testing.T) {
	mockExec := common.NewMockCommandExecutor(t)
	mockWS := &MockWSClient{}
	ctxManager := agent.NewContextManager()
	workerPool := pool.NewPool(2, 10)
	defer func() { _ = workerPool.Shutdown(1 * time.Second) }()
	defer ctxManager.Shutdown()

	handler := NewSystemHandler(mockExec, mockWS, ctxManager, workerPool)
	ctx := context.Background()

	args := &common.CommandArgs{
		Target: "alpamon",
	}

	exitCode, output, err := handler.Execute(ctx, common.Restart.String(), args)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if exitCode != 0 {
		t.Errorf("expected exit code 0, got %d", exitCode)
	}
	if !strings.Contains(output, "restart") {
		t.Errorf("expected output to mention restart, got %q", output)
	}
}

func TestSystemHandler_Quit(t *testing.T) {
	mockExec := common.NewMockCommandExecutor(t)
	mockWS := &MockWSClient{}
	ctxManager := agent.NewContextManager()
	workerPool := pool.NewPool(2, 10)
	defer func() { _ = workerPool.Shutdown(1 * time.Second) }()
	defer ctxManager.Shutdown()

	handler := NewSystemHandler(mockExec, mockWS, ctxManager, workerPool)
	ctx := context.Background()

	args := &common.CommandArgs{}

	exitCode, output, err := handler.Execute(ctx, common.Quit.String(), args)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if exitCode != 0 {
		t.Errorf("expected exit code 0, got %d", exitCode)
	}
	if !strings.Contains(output, "shutdown") {
		t.Errorf("expected output to mention shutdown, got %q", output)
	}
}

func TestSystemHandler_Reboot(t *testing.T) {
	mockExec := common.NewMockCommandExecutor(t)
	mockWS := &MockWSClient{}
	ctxManager := agent.NewContextManager()
	workerPool := pool.NewPool(2, 10)
	defer func() { _ = workerPool.Shutdown(1 * time.Second) }()
	defer ctxManager.Shutdown()

	handler := NewSystemHandler(mockExec, mockWS, ctxManager, workerPool)
	ctx := context.Background()

	args := &common.CommandArgs{}

	exitCode, output, err := handler.Execute(ctx, common.Reboot.String(), args)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if exitCode != 0 {
		t.Errorf("expected exit code 0, got %d", exitCode)
	}
	if !strings.Contains(output, "reboot") {
		t.Errorf("expected output to mention reboot, got %q", output)
	}
}

func TestSystemHandler_Shutdown(t *testing.T) {
	mockExec := common.NewMockCommandExecutor(t)
	mockWS := &MockWSClient{}
	ctxManager := agent.NewContextManager()
	workerPool := pool.NewPool(2, 10)
	defer func() { _ = workerPool.Shutdown(1 * time.Second) }()
	defer ctxManager.Shutdown()

	handler := NewSystemHandler(mockExec, mockWS, ctxManager, workerPool)
	ctx := context.Background()

	args := &common.CommandArgs{}

	exitCode, output, err := handler.Execute(ctx, common.Shutdown.String(), args)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if exitCode != 0 {
		t.Errorf("expected exit code 0, got %d", exitCode)
	}
	if !strings.Contains(output, "shutdown") {
		t.Errorf("expected output to mention shutdown, got %q", output)
	}
}

func TestSystemHandler_UnknownCommand(t *testing.T) {
	mockExec := common.NewMockCommandExecutor(t)
	mockWS := &MockWSClient{}
	ctxManager := agent.NewContextManager()
	workerPool := pool.NewPool(2, 10)
	defer func() { _ = workerPool.Shutdown(1 * time.Second) }()
	defer ctxManager.Shutdown()

	handler := NewSystemHandler(mockExec, mockWS, ctxManager, workerPool)
	ctx := context.Background()

	args := &common.CommandArgs{}

	exitCode, _, err := handler.Execute(ctx, "unknown_command", args)

	if err == nil {
		t.Error("expected error for unknown command")
	}
	if exitCode != 1 {
		t.Errorf("expected exit code 1, got %d", exitCode)
	}
	if !strings.Contains(err.Error(), "unknown system command") {
		t.Errorf("error should mention 'unknown system command', got: %v", err)
	}
}

func TestSystemHandler_Validate(t *testing.T) {
	mockExec := common.NewMockCommandExecutor(t)
	mockWS := &MockWSClient{}
	ctxManager := agent.NewContextManager()
	workerPool := pool.NewPool(2, 10)
	defer func() { _ = workerPool.Shutdown(1 * time.Second) }()
	defer ctxManager.Shutdown()

	handler := NewSystemHandler(mockExec, mockWS, ctxManager, workerPool)

	testCases := []struct {
		name string
		cmd  string
		args *common.CommandArgs
	}{
		{"upgrade", common.Upgrade.String(), &common.CommandArgs{}},
		{"restart", common.Restart.String(), &common.CommandArgs{Target: "alpamon"}},
		{"quit", common.Quit.String(), &common.CommandArgs{}},
		{"reboot", common.Reboot.String(), &common.CommandArgs{}},
		{"shutdown", common.Shutdown.String(), &common.CommandArgs{}},
		{"update", common.Update.String(), &common.CommandArgs{}},
		{"byebye", common.ByeBye.String(), &common.CommandArgs{}},
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

func TestSystemHandler_PoolShutdown(t *testing.T) {
	mockExec := common.NewMockCommandExecutor(t)
	mockWS := &MockWSClient{}
	ctxManager := agent.NewContextManager()
	workerPool := pool.NewPool(2, 10)

	handler := NewSystemHandler(mockExec, mockWS, ctxManager, workerPool)
	ctx := context.Background()

	// Shutdown pool first
	_ = workerPool.Shutdown(100 * time.Millisecond)
	ctxManager.Shutdown()

	args := &common.CommandArgs{
		Target: "alpamon",
	}

	// Should handle pool submission failure gracefully
	exitCode, output, err := handler.Execute(ctx, common.Restart.String(), args)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Should still return success message even if pool submission fails
	if exitCode != 0 {
		t.Errorf("expected exit code 0, got %d", exitCode)
	}
	if !strings.Contains(output, "restart") {
		t.Errorf("expected output to mention restart, got %q", output)
	}
}

func TestSystemHandler_Upgrade_UpToDate(t *testing.T) {
	mockExec := common.NewMockCommandExecutor(t)
	mockWS := &MockWSClient{}
	ctxManager := agent.NewContextManager()
	workerPool := pool.NewPool(2, 10)
	defer func() { _ = workerPool.Shutdown(1 * time.Second) }()
	defer ctxManager.Shutdown()

	handler := NewSystemHandler(mockExec, mockWS, ctxManager, workerPool)
	ctx := context.Background()

	args := &common.CommandArgs{}

	// This test depends on the actual version comparison
	// GetLatestVersion() makes an HTTP call, so this test will behave differently
	// depending on network availability
	exitCode, output, err := handler.Execute(ctx, common.Upgrade.String(), args)

	// Should not return an error regardless of version comparison result
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// exitCode could be 0 (up-to-date or upgrade success) or 1 (platform not supported)
	if exitCode != 0 && exitCode != 1 {
		t.Errorf("expected exit code 0 or 1, got %d", exitCode)
	}
	// Output should mention either "up-to-date", "Upgrading", or "not supported"
	if !strings.Contains(output, "up-to-date") &&
		!strings.Contains(output, "Upgrading") &&
		!strings.Contains(output, "not supported") &&
		!strings.Contains(output, "Alpamon") {
		t.Errorf("expected meaningful output, got %q", output)
	}
}

func TestSystemHandler_Update(t *testing.T) {
	mockExec := common.NewMockCommandExecutor(t)
	mockWS := &MockWSClient{}
	ctxManager := agent.NewContextManager()
	workerPool := pool.NewPool(2, 10)
	defer func() { _ = workerPool.Shutdown(1 * time.Second) }()
	defer ctxManager.Shutdown()

	handler := NewSystemHandler(mockExec, mockWS, ctxManager, workerPool)
	ctx := context.Background()

	args := &common.CommandArgs{}

	// This test depends on the actual platform
	exitCode, output, err := handler.Execute(ctx, common.Update.String(), args)

	// Should not return an error
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// exitCode could be 0 (success) or 1 (platform not supported)
	if exitCode != 0 && exitCode != 1 {
		t.Errorf("expected exit code 0 or 1, got %d", exitCode)
	}
	// Output should be present
	if output == "" && exitCode == 1 {
		t.Errorf("expected some output for unsupported platform")
	}
}

func TestSystemHandler_Uninstall(t *testing.T) {
	mockExec := common.NewMockCommandExecutor(t)
	mockWS := &MockWSClient{}
	ctxManager := agent.NewContextManager()
	workerPool := pool.NewPool(2, 10)
	defer func() { _ = workerPool.Shutdown(1 * time.Second) }()
	defer ctxManager.Shutdown()

	handler := NewSystemHandler(mockExec, mockWS, ctxManager, workerPool)
	ctx := context.Background()

	args := &common.CommandArgs{}

	exitCode, output, err := handler.Execute(ctx, common.ByeBye.String(), args)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if exitCode != 0 {
		t.Errorf("expected exit code 0, got %d", exitCode)
	}
	if !strings.Contains(output, "uninstall") {
		t.Errorf("expected output to mention uninstall, got %q", output)
	}
}
