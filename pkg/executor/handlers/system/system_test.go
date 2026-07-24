package system

import (
	"context"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alpacax/alpamon/v2/internal/pool"
	"github.com/alpacax/alpamon/v2/pkg/agent"
	"github.com/alpacax/alpamon/v2/pkg/executor/handlers/common"
	"github.com/alpacax/alpamon/v2/pkg/updater"
	"github.com/alpacax/alpamon/v2/pkg/utils"
	"github.com/alpacax/alpamon/v2/pkg/version"
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

// MockVersionResolver is a mock implementation of VersionResolver for testing
type MockVersionResolver struct {
	LatestVersion       string
	PamVersion          string
	InvalidatePamCalled bool
}

func (m *MockVersionResolver) GetLatestVersion() string {
	return m.LatestVersion
}

func (m *MockVersionResolver) GetPamVersion() string {
	return m.PamVersion
}

func (m *MockVersionResolver) InvalidatePamCache() {
	m.InvalidatePamCalled = true
}

func newMockVersionResolver() *MockVersionResolver {
	return &MockVersionResolver{LatestVersion: "v0.0.0-test", PamVersion: ""}
}

// MockAPISession records Delete calls and returns a configurable response so
// tests can verify the byebye unregister flow without hitting the network.
type MockAPISession struct {
	mu               sync.Mutex
	DeleteCalls      []string
	DeleteStatusCode int
	DeleteErr        error
}

// MultipartRequest exists only to satisfy the APISession interface; SystemHandler
// never calls it. Tripwiring with panic makes any accidental future use loud
// instead of silently returning a fake success.
func (m *MockAPISession) MultipartRequest(url string, body io.Reader, contentType string, contentLength int64, timeout time.Duration) ([]byte, int, error) {
	panic("MockAPISession.MultipartRequest: unexpected call (system handler should not invoke MultipartRequest)")
}

func (m *MockAPISession) Delete(url string, rawBody any, timeout time.Duration) ([]byte, int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.DeleteCalls = append(m.DeleteCalls, url)
	statusCode := m.DeleteStatusCode
	if statusCode == 0 {
		statusCode = 204
	}
	return nil, statusCode, m.DeleteErr
}

func (m *MockAPISession) deleteCallCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.DeleteCalls)
}

func (m *MockAPISession) lastDeleteURL() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.DeleteCalls) == 0 {
		return ""
	}
	return m.DeleteCalls[len(m.DeleteCalls)-1]
}

func TestSystemHandler_Name(t *testing.T) {
	mockExec := common.NewMockCommandExecutor(t)
	mockWS := &MockWSClient{}
	ctxManager := agent.NewContextManager()
	workerPool := pool.NewPool(2, 10)
	defer func() { _ = workerPool.Shutdown(1 * time.Second) }()
	defer ctxManager.Shutdown()

	handler := NewSystemHandler(mockExec, mockWS, ctxManager, workerPool, newMockVersionResolver(), nil)
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

	handler := NewSystemHandler(mockExec, mockWS, ctxManager, workerPool, newMockVersionResolver(), nil)
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

	handler := NewSystemHandler(mockExec, mockWS, ctxManager, workerPool, newMockVersionResolver(), nil)
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

	handler := NewSystemHandler(mockExec, mockWS, ctxManager, workerPool, newMockVersionResolver(), nil)
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

	handler := NewSystemHandler(mockExec, mockWS, ctxManager, workerPool, newMockVersionResolver(), nil)
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

	handler := NewSystemHandler(mockExec, mockWS, ctxManager, workerPool, newMockVersionResolver(), nil)
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

	handler := NewSystemHandler(mockExec, mockWS, ctxManager, workerPool, newMockVersionResolver(), nil)
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

	handler := NewSystemHandler(mockExec, mockWS, ctxManager, workerPool, newMockVersionResolver(), nil)
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

	handler := NewSystemHandler(mockExec, mockWS, ctxManager, workerPool, newMockVersionResolver(), nil)
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

	handler := NewSystemHandler(mockExec, mockWS, ctxManager, workerPool, newMockVersionResolver(), nil)

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

	handler := NewSystemHandler(mockExec, mockWS, ctxManager, workerPool, newMockVersionResolver(), nil)
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

	mockVersions := &MockVersionResolver{
		LatestVersion: version.Version, // same as current -> up-to-date
		PamVersion:    "",
	}
	handler := NewSystemHandler(mockExec, mockWS, ctxManager, workerPool, mockVersions, nil)
	ctx := context.Background()

	args := &common.CommandArgs{}

	exitCode, output, err := handler.Execute(ctx, common.Upgrade.String(), args)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if exitCode != 0 {
		t.Errorf("expected exit code 0, got %d", exitCode)
	}
	if !strings.Contains(output, "up-to-date") {
		t.Errorf("expected output to contain 'up-to-date', got %q", output)
	}
}

func TestSystemHandler_Update(t *testing.T) {
	mockExec := common.NewMockCommandExecutor(t)
	mockWS := &MockWSClient{}
	ctxManager := agent.NewContextManager()
	workerPool := pool.NewPool(2, 10)
	defer func() { _ = workerPool.Shutdown(1 * time.Second) }()
	defer ctxManager.Shutdown()

	handler := NewSystemHandler(mockExec, mockWS, ctxManager, workerPool, newMockVersionResolver(), nil)
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

	handler := NewSystemHandler(mockExec, mockWS, ctxManager, workerPool, newMockVersionResolver(), nil)
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

// TestSystemHandler_UnregisterFromConsole_CallsDelete verifies that byebye
// hits DELETE /api/servers/servers/-/unregister/ so the console drops the
// server record before the local package is purged. Exercising
// unregisterFromConsole directly avoids touching the executeUninstall path,
// which would invoke real package managers on the host.
func TestSystemHandler_UnregisterFromConsole_CallsDelete(t *testing.T) {
	mockExec := common.NewMockCommandExecutor(t)
	mockWS := &MockWSClient{}
	ctxManager := agent.NewContextManager()
	workerPool := pool.NewPool(2, 10)
	defer func() { _ = workerPool.Shutdown(1 * time.Second) }()
	defer ctxManager.Shutdown()

	mockSession := &MockAPISession{}
	handler := NewSystemHandler(mockExec, mockWS, ctxManager, workerPool, newMockVersionResolver(), mockSession)

	handler.unregisterFromConsole()

	if mockSession.deleteCallCount() != 1 {
		t.Fatalf("expected 1 Delete call, got %d", mockSession.deleteCallCount())
	}
	if got := mockSession.lastDeleteURL(); got != unregisterURL {
		t.Errorf("expected DELETE to %q, got %q", unregisterURL, got)
	}
}

// TestSystemHandler_UnregisterFromConsole_NilSession ensures the helper is a
// no-op when the API session is absent, so tests and unusual startup paths
// don't panic.
func TestSystemHandler_UnregisterFromConsole_NilSession(t *testing.T) {
	mockExec := common.NewMockCommandExecutor(t)
	mockWS := &MockWSClient{}
	ctxManager := agent.NewContextManager()
	workerPool := pool.NewPool(2, 10)
	defer func() { _ = workerPool.Shutdown(1 * time.Second) }()
	defer ctxManager.Shutdown()

	handler := NewSystemHandler(mockExec, mockWS, ctxManager, workerPool, newMockVersionResolver(), nil)

	// Must not panic.
	handler.unregisterFromConsole()
}

// TestSystemHandler_UnregisterFromConsole_NonSuccessStatus pins the best-effort
// behavior on a non-2xx response: the helper must log and return cleanly
// without panicking or aborting the surrounding uninstall sequence. Without
// this test a future refactor could silently turn the warn-and-continue branch
// into an error path that bricks local uninstall on any console hiccup.
func TestSystemHandler_UnregisterFromConsole_NonSuccessStatus(t *testing.T) {
	mockExec := common.NewMockCommandExecutor(t)
	mockWS := &MockWSClient{}
	ctxManager := agent.NewContextManager()
	workerPool := pool.NewPool(2, 10)
	defer func() { _ = workerPool.Shutdown(1 * time.Second) }()
	defer ctxManager.Shutdown()

	mockSession := &MockAPISession{DeleteStatusCode: 500}
	handler := NewSystemHandler(mockExec, mockWS, ctxManager, workerPool, newMockVersionResolver(), mockSession)

	handler.unregisterFromConsole()

	if mockSession.deleteCallCount() != 1 {
		t.Fatalf("expected 1 Delete call, got %d", mockSession.deleteCallCount())
	}
}

// TestSystemHandler_UnregisterFromConsole_DeleteError pins the best-effort
// behavior on a transport-level failure (network down, DNS error, etc.): the
// helper must log and return cleanly so the local package purge still runs.
// Pairs with NonSuccessStatus above.
func TestSystemHandler_UnregisterFromConsole_DeleteError(t *testing.T) {
	mockExec := common.NewMockCommandExecutor(t)
	mockWS := &MockWSClient{}
	ctxManager := agent.NewContextManager()
	workerPool := pool.NewPool(2, 10)
	defer func() { _ = workerPool.Shutdown(1 * time.Second) }()
	defer ctxManager.Shutdown()

	mockSession := &MockAPISession{DeleteErr: errors.New("network unreachable")}
	handler := NewSystemHandler(mockExec, mockWS, ctxManager, workerPool, newMockVersionResolver(), mockSession)

	handler.unregisterFromConsole()

	if mockSession.deleteCallCount() != 1 {
		t.Fatalf("expected 1 Delete call, got %d", mockSession.deleteCallCount())
	}
}

// TestSystemHandler_Upgrade_SelfUpdate: darwin and windows route handleUpgrade through selfUpdateFn instead of returning "not supported".
func TestSystemHandler_Upgrade_SelfUpdate(t *testing.T) {
	for _, platform := range []string{"darwin", "windows"} {
		t.Run(platform, func(t *testing.T) {
			mockExec := common.NewMockCommandExecutor(t)
			mockWS := &MockWSClient{}
			ctxManager := agent.NewContextManager()
			workerPool := pool.NewPool(2, 10)
			defer func() { _ = workerPool.Shutdown(1 * time.Second) }()
			defer ctxManager.Shutdown()

			mockVersions := &MockVersionResolver{
				LatestVersion: "v9.9.9", // differs from version.Version ("dev") -> needAlpamon
				PamVersion:    "",       // non-linux -> needPam always false anyway
			}
			handler := NewSystemHandler(mockExec, mockWS, ctxManager, workerPool, mockVersions, nil)

			var called bool
			var gotVersion string
			handler.selfUpdateFn = func(_ context.Context, v string, _ updater.Options) error {
				called = true
				gotVersion = v
				return nil
			}

			originalPlatformLike := utils.PlatformLike
			utils.SetPlatformLike(platform)
			t.Cleanup(func() { utils.SetPlatformLike(originalPlatformLike) })

			exitCode, output, err := handler.Execute(context.Background(), common.Upgrade.String(), &common.CommandArgs{})

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !called {
				t.Errorf("expected selfUpdateFn to be called on %s", platform)
			}
			if gotVersion != "v9.9.9" {
				t.Errorf("expected self-update version v9.9.9, got %q", gotVersion)
			}
			if exitCode != 0 {
				t.Errorf("expected exit code 0, got %d", exitCode)
			}
			if strings.Contains(output, "not supported") {
				t.Errorf("%s should route to self-update, got %q", platform, output)
			}
		})
	}
}

// TestSystemHandler_SelfUpdate_AlreadyInProgress: a concurrent self-update is a benign no-op—exit 0, no error, no second restart.
func TestSystemHandler_SelfUpdate_AlreadyInProgress(t *testing.T) {
	mockExec := common.NewMockCommandExecutor(t)
	mockWS := &MockWSClient{}
	ctxManager := agent.NewContextManager()
	workerPool := pool.NewPool(2, 10)
	defer func() { _ = workerPool.Shutdown(1 * time.Second) }()
	defer ctxManager.Shutdown()

	handler := NewSystemHandler(mockExec, mockWS, ctxManager, workerPool, &MockVersionResolver{}, nil)
	handler.selfUpdateFn = func(_ context.Context, _ string, _ updater.Options) error {
		return updater.ErrSelfUpdateInProgress
	}

	exitCode, output, err := handler.selfUpdate(context.Background(), "v9.9.9")

	if err != nil {
		t.Fatalf("in-progress should not surface as an error, got: %v", err)
	}
	if exitCode != 0 {
		t.Errorf("expected exit code 0, got %d", exitCode)
	}
	if !strings.Contains(output, "already in progress") {
		t.Errorf("expected in-progress message, got %q", output)
	}
	if mockWS.RestartCalled {
		t.Error("in-progress path must not schedule a restart")
	}
}
