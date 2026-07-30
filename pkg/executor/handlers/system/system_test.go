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
	"github.com/alpacax/alpamon/v2/pkg/config"
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
	GotProxy            string
}

func (m *MockVersionResolver) GetLatestVersion(proxyURL string) string {
	m.GotProxy = proxyURL
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

// Reports the zypper lock exit code for the first lockedRuns `zypper` commands,
// then defers to the mock, whose one fixed result per command cannot express
// "locked now, free on the retry".
type lockedThenFreeExecutor struct {
	*common.MockCommandExecutor
	lockedRuns int
	calls      int
}

func (e *lockedThenFreeExecutor) zypperLocked(args []string) bool {
	joined := strings.Join(args, " ")
	// `zypper lr` does not take the libzypp lock, measured on opensuse/leap:15.
	if !strings.Contains(joined, "zypper") || strings.Contains(joined, " lr ") {
		return false
	}
	e.calls++
	return e.calls <= e.lockedRuns
}

func (e *lockedThenFreeExecutor) Exec(ctx context.Context, args []string, username, groupname string, env map[string]string, timeout time.Duration) (int, string, error) {
	if e.zypperLocked(args) {
		return 7, "System management is locked by the application with pid 1234", errors.New("exit status 7")
	}
	return e.MockCommandExecutor.Exec(ctx, args, username, groupname, env, timeout)
}

func (e *lockedThenFreeExecutor) RunAsUser(ctx context.Context, username string, name string, args ...string) (int, string, error) {
	if e.zypperLocked(args) {
		return 7, "System management is locked by the application with pid 1234", errors.New("exit status 7")
	}
	return e.MockCommandExecutor.RunAsUser(ctx, username, name, args...)
}

// Answers the rpm version probe with before on the first call and after on the
// rest, so an upgrade that zypper reported as successful can be shown to have
// moved the package or not.
type versionSteppingExecutor struct {
	*common.MockCommandExecutor
	before, after string
	probes        int
}

func (e *versionSteppingExecutor) RunAsUser(ctx context.Context, username string, name string, args ...string) (int, string, error) {
	if name == "rpm" {
		e.probes++
		if e.probes == 1 {
			return 0, e.before, nil
		}
		return 0, e.after, nil
	}
	return e.MockCommandExecutor.RunAsUser(ctx, username, name, args...)
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

// findExecutedShell returns the last executed "sh" command from the mock, or
// nil when no shell was spawned.
func findExecutedShell(mockExec *common.MockCommandExecutor) *common.ExecutedCommand {
	cmds := mockExec.GetExecutedCommands()
	for i := len(cmds) - 1; i >= 0; i-- {
		if cmds[i].Name == "sh" {
			return &cmds[i]
		}
	}
	return nil
}

// TestSystemHandler_Upgrade_PackageProxy verifies that a package_proxy in the
// upgrade payload reaches both the version lookup and the environment of the
// spawned package-manager shell, and that no_proxy shields the Alpacon server
// host, IMDS, and localhost.
func TestSystemHandler_Upgrade_PackageProxy(t *testing.T) {
	mockExec := common.NewMockCommandExecutor(t)
	mockWS := &MockWSClient{}
	ctxManager := agent.NewContextManager()
	workerPool := pool.NewPool(2, 10)
	defer func() { _ = workerPool.Shutdown(1 * time.Second) }()
	defer ctxManager.Shutdown()

	mockVersions := &MockVersionResolver{LatestVersion: "v9.9.9"} // differs from version.Version -> needAlpamon
	handler := NewSystemHandler(mockExec, mockWS, ctxManager, workerPool, mockVersions, nil)

	originalPlatformLike := utils.PlatformLike
	utils.SetPlatformLike("debian")
	t.Cleanup(func() { utils.SetPlatformLike(originalPlatformLike) })
	setPackageManagerAndID(t, utils.PkgApt, "")

	originalServerURL := config.GlobalSettings.ServerURL
	config.GlobalSettings.ServerURL = "https://console.example.com"
	t.Cleanup(func() { config.GlobalSettings.ServerURL = originalServerURL })

	const proxy = "http://proxy.internal:3128"
	args := &common.CommandArgs{PackageProxy: proxy}

	exitCode, _, err := handler.Execute(context.Background(), common.Upgrade.String(), args)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if exitCode != 0 {
		t.Errorf("expected exit code 0, got %d", exitCode)
	}
	if mockVersions.GotProxy != proxy {
		t.Errorf("expected version lookup to use proxy %q, got %q", proxy, mockVersions.GotProxy)
	}

	shell := findExecutedShell(mockExec)
	if shell == nil {
		t.Fatal("expected a package-manager shell to be spawned")
	}
	if shell.User != "root" {
		t.Errorf("expected shell to run as root, got %q", shell.User)
	}
	if len(shell.Args) != 2 || shell.Args[0] != "-c" || !strings.Contains(shell.Args[1], "apt-get") {
		t.Errorf("expected sh -c apt-get command, got %v", shell.Args)
	}
	for _, key := range []string{"http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY"} {
		if got := shell.Env[key]; got != proxy {
			t.Errorf("expected env %s=%q, got %q", key, proxy, got)
		}
	}
	for _, key := range []string{"no_proxy", "NO_PROXY"} {
		noProxy := shell.Env[key]
		for _, excluded := range []string{"localhost", "127.0.0.1", "169.254.169.254", "fd00:ec2::254", "metadata.google.internal", "console.example.com"} {
			if !strings.Contains(noProxy, excluded) {
				t.Errorf("expected env %s to exclude %q, got %q", key, excluded, noProxy)
			}
		}
	}
}

// TestSystemHandler_Upgrade_NoPackageProxy pins backward compatibility: an
// upgrade payload without package_proxy spawns the shell with no proxy
// environment override.
func TestSystemHandler_Upgrade_NoPackageProxy(t *testing.T) {
	mockExec := common.NewMockCommandExecutor(t)
	mockWS := &MockWSClient{}
	ctxManager := agent.NewContextManager()
	workerPool := pool.NewPool(2, 10)
	defer func() { _ = workerPool.Shutdown(1 * time.Second) }()
	defer ctxManager.Shutdown()

	mockVersions := &MockVersionResolver{LatestVersion: "v9.9.9"}
	handler := NewSystemHandler(mockExec, mockWS, ctxManager, workerPool, mockVersions, nil)

	originalPlatformLike := utils.PlatformLike
	utils.SetPlatformLike("debian")
	t.Cleanup(func() { utils.SetPlatformLike(originalPlatformLike) })
	setPackageManagerAndID(t, utils.PkgApt, "")

	exitCode, _, err := handler.Execute(context.Background(), common.Upgrade.String(), &common.CommandArgs{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if exitCode != 0 {
		t.Errorf("expected exit code 0, got %d", exitCode)
	}
	if mockVersions.GotProxy != "" {
		t.Errorf("expected version lookup without proxy, got %q", mockVersions.GotProxy)
	}

	shell := findExecutedShell(mockExec)
	if shell == nil {
		t.Fatal("expected a package-manager shell to be spawned")
	}
	if len(shell.Env) != 0 {
		t.Errorf("expected no env override without package_proxy, got %v", shell.Env)
	}
}

// TestSystemHandler_Upgrade_InvalidPackageProxy verifies that an invalid
// package_proxy is treated as absent consistently: the version lookup goes
// direct AND no proxy environment is injected into the root shell.
func TestSystemHandler_Upgrade_InvalidPackageProxy(t *testing.T) {
	for name, proxy := range map[string]string{
		"parse error":        "http://[::1",
		"missing host":       "not a url",
		"unsupported scheme": "ftp://proxy.internal:21",
	} {
		t.Run(name, func(t *testing.T) {
			mockExec := common.NewMockCommandExecutor(t)
			mockWS := &MockWSClient{}
			ctxManager := agent.NewContextManager()
			workerPool := pool.NewPool(2, 10)
			defer func() { _ = workerPool.Shutdown(1 * time.Second) }()
			defer ctxManager.Shutdown()

			mockVersions := &MockVersionResolver{LatestVersion: "v9.9.9", GotProxy: "sentinel"}
			handler := NewSystemHandler(mockExec, mockWS, ctxManager, workerPool, mockVersions, nil)

			originalPlatformLike := utils.PlatformLike
			utils.SetPlatformLike("debian")
			t.Cleanup(func() { utils.SetPlatformLike(originalPlatformLike) })
			setPackageManagerAndID(t, utils.PkgApt, "")

			exitCode, _, err := handler.Execute(context.Background(), common.Upgrade.String(), &common.CommandArgs{PackageProxy: proxy})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if exitCode != 0 {
				t.Errorf("expected exit code 0, got %d", exitCode)
			}
			if mockVersions.GotProxy != "" {
				t.Errorf("expected version lookup without proxy, got %q", mockVersions.GotProxy)
			}

			shell := findExecutedShell(mockExec)
			if shell == nil {
				t.Fatal("expected a package-manager shell to be spawned")
			}
			if len(shell.Env) != 0 {
				t.Errorf("expected no env override for invalid proxy %q, got %v", proxy, shell.Env)
			}
		})
	}
}

// TestSystemHandler_Upgrade_VersionLookupFailureProceeds verifies that a failed
// GitHub version lookup (e.g. closed-network deployments) is no longer fatal on
// linux: the upgrade proceeds and "latest" is delegated to the package manager.
func TestSystemHandler_Upgrade_VersionLookupFailureProceeds(t *testing.T) {
	mockExec := common.NewMockCommandExecutor(t)
	mockWS := &MockWSClient{}
	ctxManager := agent.NewContextManager()
	workerPool := pool.NewPool(2, 10)
	defer func() { _ = workerPool.Shutdown(1 * time.Second) }()
	defer ctxManager.Shutdown()

	mockVersions := &MockVersionResolver{LatestVersion: ""} // lookup failure
	handler := NewSystemHandler(mockExec, mockWS, ctxManager, workerPool, mockVersions, nil)

	originalPlatformLike := utils.PlatformLike
	utils.SetPlatformLike("debian")
	t.Cleanup(func() { utils.SetPlatformLike(originalPlatformLike) })
	setPackageManagerAndID(t, utils.PkgApt, "")

	exitCode, _, err := handler.Execute(context.Background(), common.Upgrade.String(), &common.CommandArgs{})
	if err != nil {
		t.Fatalf("expected version lookup failure to be non-fatal, got: %v", err)
	}
	if exitCode != 0 {
		t.Errorf("expected exit code 0, got %d", exitCode)
	}

	shell := findExecutedShell(mockExec)
	if shell == nil {
		t.Fatal("expected the package-manager upgrade to proceed despite the lookup failure")
	}
	if len(shell.Args) != 2 || !strings.Contains(shell.Args[1], "alpamon") {
		t.Errorf("expected unpinned alpamon upgrade command, got %v", shell.Args)
	}
}

// TestSystemHandler_Upgrade_VersionLookupFailureSelfUpdate pins the non-linux
// behavior: self-update needs a concrete target version, so a failed lookup
// still fails the upgrade on darwin/windows (no package manager to delegate to).
func TestSystemHandler_Upgrade_VersionLookupFailureSelfUpdate(t *testing.T) {
	mockExec := common.NewMockCommandExecutor(t)
	mockWS := &MockWSClient{}
	ctxManager := agent.NewContextManager()
	workerPool := pool.NewPool(2, 10)
	defer func() { _ = workerPool.Shutdown(1 * time.Second) }()
	defer ctxManager.Shutdown()

	handler := NewSystemHandler(mockExec, mockWS, ctxManager, workerPool, &MockVersionResolver{LatestVersion: ""}, nil)

	var called bool
	handler.selfUpdateFn = func(_ context.Context, _ string, _ updater.Options) error {
		called = true
		return nil
	}

	originalPlatformLike := utils.PlatformLike
	utils.SetPlatformLike("darwin")
	t.Cleanup(func() { utils.SetPlatformLike(originalPlatformLike) })
	setPackageManagerAndID(t, utils.PkgBrew, "")

	exitCode, output, err := handler.Execute(context.Background(), common.Upgrade.String(), &common.CommandArgs{})
	if err == nil {
		t.Fatal("expected error when version lookup fails on darwin")
	}
	if exitCode != 1 {
		t.Errorf("expected exit code 1, got %d", exitCode)
	}
	if called {
		t.Error("self-update must not run without a target version")
	}
	if !strings.Contains(output, "GitHub") {
		t.Errorf("expected lookup failure message, got %q", output)
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

	// Neutralize the deferred-uninstall timer and drain its goroutine before
	// the test returns: a leaked executeUninstall reads utils.PlatformLike
	// after the test ends and races with SetPlatformLike in later tests.
	handler.uninstallDelay = 0
	done := make(chan struct{})
	handler.uninstallDone = done

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

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("uninstall goroutine did not finish")
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

// Both axes are set explicitly. PkgNone is a non-empty sentinel, so a
// zero-value PackageManager would hit the unsupported branch, not pass here.
func TestSystemHandler_Upgrade_SelfUpdate(t *testing.T) {
	for _, tc := range []struct {
		platformLike   string
		packageManager string
	}{
		{"darwin", utils.PkgBrew},
		{"windows", utils.PkgNone},
	} {
		t.Run(tc.platformLike, func(t *testing.T) {
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
			utils.SetPlatformLike(tc.platformLike)
			t.Cleanup(func() { utils.SetPlatformLike(originalPlatformLike) })
			setPackageManagerAndID(t, tc.packageManager, "")

			exitCode, output, err := handler.Execute(context.Background(), common.Upgrade.String(), &common.CommandArgs{})

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !called {
				t.Errorf("expected selfUpdateFn to be called on %s", tc.platformLike)
			}
			if gotVersion != "v9.9.9" {
				t.Errorf("expected self-update version v9.9.9, got %q", gotVersion)
			}
			if exitCode != 0 {
				t.Errorf("expected exit code 0, got %d", exitCode)
			}
			if strings.Contains(output, "not supported") {
				t.Errorf("%s should route to self-update, got %q", tc.platformLike, output)
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

// TestSystemHandler_SelfUpdate_RestartScheduleFails: a successful update whose restart
// can't be scheduled reports a manual-restart failure and fires no restart. The latch
// release on this branch is asserted in the updater package.
func TestSystemHandler_SelfUpdate_RestartScheduleFails(t *testing.T) {
	mockExec := common.NewMockCommandExecutor(t)
	mockWS := &MockWSClient{}
	ctxManager := agent.NewContextManager()
	workerPool := pool.NewPool(2, 10)
	defer ctxManager.Shutdown()
	// Shut the pool down up front so scheduleDelayedAction's Submit fails.
	if err := workerPool.Shutdown(1 * time.Second); err != nil {
		t.Fatalf("failed to shut down pool: %v", err)
	}

	handler := NewSystemHandler(mockExec, mockWS, ctxManager, workerPool, &MockVersionResolver{}, nil)
	handler.selfUpdateFn = func(_ context.Context, _ string, _ updater.Options) error {
		return nil // update succeeded
	}

	exitCode, output, err := handler.selfUpdate(context.Background(), "v9.9.9")

	if err == nil {
		t.Fatal("expected error when restart scheduling fails")
	}
	if exitCode != 1 {
		t.Errorf("expected exit code 1, got %d", exitCode)
	}
	if !strings.Contains(output, "manually") {
		t.Errorf("expected manual-restart hint, got %q", output)
	}
	if mockWS.RestartCalled {
		t.Error("restart must not fire when scheduling failed")
	}
}

func setPackageManagerAndID(t *testing.T, pkgManager, platformID string) {
	t.Helper()
	origPM := utils.PackageManager
	origID := utils.PlatformID
	utils.SetPackageManager(pkgManager)
	utils.SetPlatformID(platformID)
	t.Cleanup(func() {
		utils.SetPackageManager(origPM)
		utils.SetPlatformID(origID)
	})
}

// openSUSE/SLES report platform_like=rhel but must run zypper locally, which is
// why PackageManager is a separate axis.
func TestSystemHandler_Upgrade_UsesZypper(t *testing.T) {
	mockExec := common.NewMockCommandExecutor(t)
	mockWS := &MockWSClient{}
	ctxManager := agent.NewContextManager()
	workerPool := pool.NewPool(2, 10)
	defer func() { _ = workerPool.Shutdown(1 * time.Second) }()
	defer ctxManager.Shutdown()

	mockVersions := &MockVersionResolver{LatestVersion: "v9.9.9", PamVersion: ""}
	handler := NewSystemHandler(mockExec, mockWS, ctxManager, workerPool, mockVersions, nil)

	setPackageManagerAndID(t, utils.PkgZypper, "opensuse-leap")

	exitCode, _, err := handler.Execute(context.Background(), common.Upgrade.String(), &common.CommandArgs{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", exitCode)
	}

	refreshedAt, updatedAt := -1, -1
	for i, c := range mockExec.GetExecutedCommands() {
		joined := c.Name + " " + strings.Join(c.Args, " ")
		if strings.Contains(joined, "zypper --non-interactive refresh") {
			refreshedAt = i
		}
		if strings.Contains(joined, "zypper --non-interactive update alpamon") {
			updatedAt = i
		}
		if strings.Contains(joined, "yum ") || strings.Contains(joined, "apt-get ") {
			t.Errorf("zypper host must not run yum/apt: %q", joined)
		}
	}
	if updatedAt < 0 {
		t.Fatalf("expected a zypper update command, got %+v", mockExec.GetExecutedCommands())
	}
	// Against stale metadata a bare `update` exits 0 without upgrading, so the
	// refresh must survive refactors.
	if refreshedAt < 0 || refreshedAt > updatedAt {
		t.Errorf("update must be preceded by a refresh, got %+v", mockExec.GetExecutedCommands())
	}
}

// One unreachable repo anywhere on the host exits an unscoped refresh 4, so the
// chained update never runs. Scoping both halves to alpamon's own repo is what
// keeps a dead third-party repo from making the agent unupgradable.
func TestSystemHandler_Upgrade_ScopesZypperToAlpamonRepo(t *testing.T) {
	const alpamonSection = "[alpamon]\nenabled=1\nautorefresh=1\nbaseurl=https://packagecloud.io/alpacax/alpamon/rpm_any/rpm_any/$basearch\n"
	const deadSection = "[deadrepo]\nenabled=1\nautorefresh=0\nbaseurl=http://dead.invalid.example/repo\n"

	tests := []struct {
		name        string
		repoExport  string
		wantRefresh string
	}{
		{
			name:        "refresh is scoped to the resolved alias",
			repoExport:  deadSection + "\n" + alpamonSection,
			wantRefresh: "zypper --non-interactive refresh alpamon",
		},
		{
			name:        "operator alias is honored",
			repoExport:  "[alpacax-alpamon]\nenabled=1\nbaseurl=https://packagecloud.io/alpacax/alpamon/rpm_any/rpm_any/$basearch\n",
			wantRefresh: "zypper --non-interactive refresh alpacax-alpamon",
		},
		{
			name:        "no alpamon repo falls back to an unscoped refresh",
			repoExport:  deadSection,
			wantRefresh: "zypper --non-interactive refresh",
		},
		{
			// A disabled repo serves nothing, so scoping to it would turn a
			// working upgrade into a failing one.
			name:        "disabled alpamon repo falls back",
			repoExport:  "[alpamon]\nenabled=0\nbaseurl=https://packagecloud.io/alpacax/alpamon/rpm_any/rpm_any/$basearch\n",
			wantRefresh: "zypper --non-interactive refresh",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockExec := common.NewMockCommandExecutor(t)
			mockWS := &MockWSClient{}
			ctxManager := agent.NewContextManager()
			workerPool := pool.NewPool(2, 10)
			defer func() { _ = workerPool.Shutdown(1 * time.Second) }()
			defer ctxManager.Shutdown()

			mockVersions := &MockVersionResolver{LatestVersion: "v9.9.9", PamVersion: ""}
			handler := NewSystemHandler(mockExec, mockWS, ctxManager, workerPool, mockVersions, nil)
			setPackageManagerAndID(t, utils.PkgZypper, "opensuse-leap")
			mockExec.SetResult("zypper --non-interactive lr --export -", 0, tt.repoExport, nil)

			if _, _, err := handler.Execute(context.Background(), common.Upgrade.String(), &common.CommandArgs{}); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			var refreshed, updated bool
			for _, c := range mockExec.GetExecutedCommands() {
				switch c.Name + " " + strings.Join(c.Args, " ") {
				case tt.wantRefresh:
					refreshed = true
				// `update -r <alias>` would load only that repo and fail to
				// resolve dependencies from the distribution repos.
				case "sh -c zypper --non-interactive update alpamon":
					updated = true
				}
			}
			if !refreshed {
				t.Errorf("expected %q, got %+v", tt.wantRefresh, mockExec.GetExecutedCommands())
			}
			if !updated {
				t.Errorf("expected an unscoped update, got %+v", mockExec.GetExecutedCommands())
			}
		})
	}
}

// The refresh exists to keep a stale-metadata no-op from reporting success, so
// its failure must stop the upgrade instead of falling through to the update.
func TestSystemHandler_Upgrade_ZypperRefreshFailureStopsTheUpgrade(t *testing.T) {
	mockExec := common.NewMockCommandExecutor(t)
	mockWS := &MockWSClient{}
	ctxManager := agent.NewContextManager()
	workerPool := pool.NewPool(2, 10)
	defer func() { _ = workerPool.Shutdown(1 * time.Second) }()
	defer ctxManager.Shutdown()

	mockVersions := &MockVersionResolver{LatestVersion: "v9.9.9", PamVersion: ""}
	handler := NewSystemHandler(mockExec, mockWS, ctxManager, workerPool, mockVersions, nil)
	setPackageManagerAndID(t, utils.PkgZypper, "opensuse-leap")
	mockExec.SetResult("zypper --non-interactive refresh", 4, "repo error", errors.New("exit status 4"))

	exitCode, _, _ := handler.Execute(context.Background(), common.Upgrade.String(), &common.CommandArgs{})
	if exitCode != 4 {
		t.Errorf("expected the refresh exit code 4, got %d", exitCode)
	}
	for _, c := range mockExec.GetExecutedCommands() {
		if strings.Contains(strings.Join(c.Args, " "), "update") {
			t.Errorf("update must not run after a failed refresh: %+v", c)
		}
	}
}

// A repo skipped elsewhere on the host cannot hide a missed alpamon update once
// alpamon's own repo has been refreshed on its own, so 106 is success there and
// a failure when there was nothing to scope to.
func TestSystemHandler_Upgrade_ZypperSkippedRepoDependsOnScope(t *testing.T) {
	tests := []struct {
		name       string
		repoExport string
		want       int
	}{
		{
			name:       "scoped refresh tolerates a skipped repo",
			repoExport: "[alpamon]\nenabled=1\nbaseurl=https://packagecloud.io/alpacax/alpamon/rpm_any/rpm_any/$basearch\n",
			want:       0,
		},
		{
			name:       "unscoped refresh does not",
			repoExport: "[repo-oss]\nenabled=1\nbaseurl=http://download.opensuse.org/distribution/leap/$releasever/repo/oss/\n",
			want:       106,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockExec := common.NewMockCommandExecutor(t)
			mockWS := &MockWSClient{}
			ctxManager := agent.NewContextManager()
			workerPool := pool.NewPool(2, 10)
			defer func() { _ = workerPool.Shutdown(1 * time.Second) }()
			defer ctxManager.Shutdown()

			mockVersions := &MockVersionResolver{LatestVersion: "v9.9.9", PamVersion: ""}
			handler := NewSystemHandler(mockExec, mockWS, ctxManager, workerPool, mockVersions, nil)
			setPackageManagerAndID(t, utils.PkgZypper, "opensuse-leap")
			mockExec.SetResult("zypper --non-interactive lr --export -", 0, tt.repoExport, nil)
			mockExec.SetResult("sh -c zypper --non-interactive update alpamon", 106, "", errors.New("exit status 106"))

			exitCode, _, _ := handler.Execute(context.Background(), common.Upgrade.String(), &common.CommandArgs{})
			if exitCode != tt.want {
				t.Errorf("expected %d, got %d", tt.want, exitCode)
			}
		})
	}
}

// A kernel or zypper self-update ends the command with an informational code,
// which must not reach the console as a failure.
func TestSystemHandler_SystemUpdate_ZypperInformationalExitCodes(t *testing.T) {
	tests := []struct {
		name       string
		pkgManager string
		platformID string
		cmd        string
		exitCode   int
		want       int
	}{
		{"reboot needed", utils.PkgZypper, "opensuse-leap", "zypper --non-interactive refresh && zypper --non-interactive update", 102, 0},
		{"package manager restart needed", utils.PkgZypper, "opensuse-leap", "zypper --non-interactive refresh && zypper --non-interactive update", 103, 0},
		// Informational does not mean successful; see docs/opensuse.md.
		{"patch-check code stays a failure", utils.PkgZypper, "opensuse-leap", "zypper --non-interactive refresh && zypper --non-interactive update", 100, 100},
		{"capability not found stays a failure", utils.PkgZypper, "opensuse-leap", "zypper --non-interactive refresh && zypper --non-interactive update", 104, 104},
		{"skipped repo stays a failure", utils.PkgZypper, "opensuse-leap", "zypper --non-interactive refresh && zypper --non-interactive update", 106, 106},
		{"failed post script stays a failure", utils.PkgZypper, "opensuse-leap", "zypper --non-interactive refresh && zypper --non-interactive update", 107, 107},
		{"unreachable repo stays a failure", utils.PkgZypper, "opensuse-leap", "zypper --non-interactive refresh && zypper --non-interactive update", 4, 4},
		// apt has no informational family, so 102 there is a real failure.
		{"apt is untouched", utils.PkgApt, "ubuntu", "apt-get update -o Acquire::Retries=3 && apt-get upgrade -y -o Acquire::Retries=3 && apt-get autoremove -y", 102, 102},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockExec := common.NewMockCommandExecutor(t)
			mockWS := &MockWSClient{}
			ctxManager := agent.NewContextManager()
			workerPool := pool.NewPool(2, 10)
			defer func() { _ = workerPool.Shutdown(1 * time.Second) }()
			defer ctxManager.Shutdown()

			handler := NewSystemHandler(mockExec, mockWS, ctxManager, workerPool, &MockVersionResolver{}, nil)
			setPackageManagerAndID(t, tt.pkgManager, tt.platformID)
			mockExec.SetResult("sh -c "+tt.cmd, tt.exitCode, "", errors.New("exit status"))

			exitCode, _, err := handler.Execute(context.Background(), common.Update.String(), &common.CommandArgs{})
			if exitCode != tt.want {
				t.Errorf("exit %d: expected %d, got %d", tt.exitCode, tt.want, exitCode)
			}
			if tt.want == 0 && err != nil {
				t.Errorf("a normalized exit must drop the error, got %v", err)
			}
			if tt.want != 0 && err == nil {
				t.Error("a real failure must keep its error")
			}
		})
	}
}

// The agent's own upgrade shares the normalization, where the exit code also
// gates the pam version cache invalidation.
func TestSystemHandler_Upgrade_ZypperRebootNeededIsSuccess(t *testing.T) {
	mockExec := common.NewMockCommandExecutor(t)
	mockWS := &MockWSClient{}
	ctxManager := agent.NewContextManager()
	workerPool := pool.NewPool(2, 10)
	defer func() { _ = workerPool.Shutdown(1 * time.Second) }()
	defer ctxManager.Shutdown()

	mockVersions := &MockVersionResolver{LatestVersion: "v9.9.9", PamVersion: "v1.0.0"}
	handler := NewSystemHandler(mockExec, mockWS, ctxManager, workerPool, mockVersions, nil)
	setPackageManagerAndID(t, utils.PkgZypper, "opensuse-leap")

	mockExec.SetResult(
		"sh -c zypper --non-interactive refresh && zypper --non-interactive update alpamon alpamon-pam",
		102, "", errors.New("exit status 102"),
	)

	exitCode, _, err := handler.Execute(context.Background(), common.Upgrade.String(), &common.CommandArgs{})
	if exitCode != 0 {
		t.Errorf("expected exit code 0 for reboot-needed, got %d", exitCode)
	}
	if err != nil {
		t.Errorf("a normalized exit must drop the error, got %v", err)
	}
	if !mockVersions.InvalidatePamCalled {
		t.Error("pam cache must be invalidated when the upgrade succeeded")
	}
}

// Leap/SLES must NOT use dup: it would jump to the next service pack.
func TestSystemHandler_SystemUpdate_ZypperDupOnlyOnTumbleweed(t *testing.T) {
	tests := []struct {
		name       string
		platformID string
		wantCmd    string
		rejectCmd  string
	}{
		{"tumbleweed", "opensuse-tumbleweed", "zypper --non-interactive dup", "zypper --non-interactive update"},
		{"leap", "opensuse-leap", "zypper --non-interactive update", "zypper --non-interactive dup"},
		{"sles", "sles", "zypper --non-interactive update", "zypper --non-interactive dup"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockExec := common.NewMockCommandExecutor(t)
			mockWS := &MockWSClient{}
			ctxManager := agent.NewContextManager()
			workerPool := pool.NewPool(2, 10)
			defer func() { _ = workerPool.Shutdown(1 * time.Second) }()
			defer ctxManager.Shutdown()

			handler := NewSystemHandler(mockExec, mockWS, ctxManager, workerPool, &MockVersionResolver{}, nil)
			setPackageManagerAndID(t, utils.PkgZypper, tt.platformID)

			if _, _, err := handler.Execute(context.Background(), common.Update.String(), &common.CommandArgs{}); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			var found bool
			for _, c := range mockExec.GetExecutedCommands() {
				joined := strings.Join(c.Args, " ")
				if strings.Contains(joined, tt.rejectCmd) {
					t.Fatalf("%s must not run %q", tt.name, tt.rejectCmd)
				}
				if strings.Contains(joined, tt.wantCmd) {
					found = true
				}
			}
			if !found {
				t.Errorf("expected %q, got %+v", tt.wantCmd, mockExec.GetExecutedCommands())
			}
		})
	}
}

// Asserts against every captured command: the uninstall is scheduled through
// systemd-run where systemd exists and a deferred subshell where it does not, so
// the zypper string lands in different argv positions per host.
func TestSystemHandler_Uninstall_UsesZypper(t *testing.T) {
	mockExec := common.NewMockCommandExecutor(t)
	mockWS := &MockWSClient{}
	ctxManager := agent.NewContextManager()
	workerPool := pool.NewPool(2, 10)
	defer func() { _ = workerPool.Shutdown(1 * time.Second) }()
	defer ctxManager.Shutdown()

	handler := NewSystemHandler(mockExec, mockWS, ctxManager, workerPool, newMockVersionResolver(), nil)
	setPackageManagerAndID(t, utils.PkgZypper, "opensuse-leap")

	handler.executeUninstall()

	var found bool
	for _, c := range mockExec.GetExecutedCommands() {
		joined := strings.Join(c.Args, " ")
		if strings.Contains(joined, "zypper --non-interactive remove alpamon") {
			found = true
		}
		if strings.Contains(joined, "yum remove") || strings.Contains(joined, "apt-get purge") {
			t.Errorf("zypper host must not run yum/apt: %q", joined)
		}
	}
	if !found {
		t.Errorf("expected a zypper remove command, got %+v", mockExec.GetExecutedCommands())
	}
}

func TestRetryWhileZypperLocked(t *testing.T) {
	orig := zypperLockRetryDelay
	zypperLockRetryDelay = 0
	t.Cleanup(func() { zypperLockRetryDelay = orig })

	tests := []struct {
		name       string
		pkgManager string
		lockedRuns int
		wantCalls  int
		wantExit   int
	}{
		{"retries until the lock clears", utils.PkgZypper, 1, 2, 0},
		{"gives up after the attempt cap", utils.PkgZypper, 99, zypperLockAttempts, 7},
		// apt has no ZYPP_LOCKED, so 7 there is a real failure to report as-is.
		{"apt exit 7 is not retried", utils.PkgApt, 99, 1, 7},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setPackageManagerAndID(t, tt.pkgManager, "opensuse-leap")

			var calls int
			exitCode, _, _ := retryWhileZypperLocked(context.Background(), func() (int, string, error) {
				calls++
				if calls <= tt.lockedRuns {
					return 7, "locked", errors.New("exit status 7")
				}
				return 0, "", nil
			})

			if calls != tt.wantCalls {
				t.Errorf("expected %d attempts, got %d", tt.wantCalls, calls)
			}
			if exitCode != tt.wantExit {
				t.Errorf("expected exit %d, got %d", tt.wantExit, exitCode)
			}
		})
	}
}

// A console update racing the agent's own upgrade, or packagekit holding the
// lock, must not surface as a failed command when the lock clears.
func TestSystemHandler_ZypperLockIsRetried(t *testing.T) {
	orig := zypperLockRetryDelay
	zypperLockRetryDelay = 0
	t.Cleanup(func() { zypperLockRetryDelay = orig })

	tests := []struct {
		name    string
		command string
	}{
		{"system update", common.Update.String()},
		{"agent upgrade", common.Upgrade.String()},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockExec := &lockedThenFreeExecutor{MockCommandExecutor: common.NewMockCommandExecutor(t), lockedRuns: 1}
			mockWS := &MockWSClient{}
			ctxManager := agent.NewContextManager()
			workerPool := pool.NewPool(2, 10)
			defer func() { _ = workerPool.Shutdown(1 * time.Second) }()
			defer ctxManager.Shutdown()

			mockVersions := &MockVersionResolver{LatestVersion: "v9.9.9", PamVersion: ""}
			handler := NewSystemHandler(mockExec, mockWS, ctxManager, workerPool, mockVersions, nil)
			setPackageManagerAndID(t, utils.PkgZypper, "opensuse-leap")

			exitCode, _, _ := handler.Execute(context.Background(), tt.command, &common.CommandArgs{})
			if exitCode != 0 {
				t.Errorf("expected the retry to recover, got exit %d", exitCode)
			}
			if mockExec.calls < 2 {
				t.Errorf("expected a retry, got %d lockable calls", mockExec.calls)
			}
		})
	}
}

// zypper exits 0 with "No update candidate" when vendor stickiness blocks the
// upgrade, so the exit code alone cannot say whether the package moved.
func TestSystemHandler_Upgrade_ZypperNoOpIsReported(t *testing.T) {
	tests := []struct {
		name         string
		afterVersion string
		wantNote     bool
	}{
		{"version moved", "2.4.1-1", false},
		{"version unchanged", "2.4.0-1", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockExec := &versionSteppingExecutor{
				MockCommandExecutor: common.NewMockCommandExecutor(t),
				before:              "2.4.0-1",
				after:               tt.afterVersion,
			}
			mockWS := &MockWSClient{}
			ctxManager := agent.NewContextManager()
			workerPool := pool.NewPool(2, 10)
			defer func() { _ = workerPool.Shutdown(1 * time.Second) }()
			defer ctxManager.Shutdown()

			mockVersions := &MockVersionResolver{LatestVersion: "v9.9.9", PamVersion: ""}
			handler := NewSystemHandler(mockExec, mockWS, ctxManager, workerPool, mockVersions, nil)
			setPackageManagerAndID(t, utils.PkgZypper, "opensuse-leap")

			exitCode, output, _ := handler.Execute(context.Background(), common.Upgrade.String(), &common.CommandArgs{})
			// A repo that has not published the build yet is routine, so the
			// command stays successful either way.
			if exitCode != 0 {
				t.Fatalf("expected exit 0, got %d (%q)", exitCode, output)
			}
			if gotNote := strings.Contains(output, "did not move"); gotNote != tt.wantNote {
				t.Errorf("note present = %v, want %v: %q", gotNote, tt.wantNote, output)
			}
			if tt.wantNote && !strings.Contains(output, "2.4.0-1") {
				t.Errorf("note must name the version still installed, got %q", output)
			}
		})
	}
}

// An apt host must not pay for the rpm query, and must keep reporting the
// package manager's own exit code.
func TestSystemHandler_Upgrade_NoVersionProbeOnApt(t *testing.T) {
	mockExec := common.NewMockCommandExecutor(t)
	mockWS := &MockWSClient{}
	ctxManager := agent.NewContextManager()
	workerPool := pool.NewPool(2, 10)
	defer func() { _ = workerPool.Shutdown(1 * time.Second) }()
	defer ctxManager.Shutdown()

	mockVersions := &MockVersionResolver{LatestVersion: "v9.9.9", PamVersion: ""}
	handler := NewSystemHandler(mockExec, mockWS, ctxManager, workerPool, mockVersions, nil)
	setPackageManagerAndID(t, utils.PkgApt, "ubuntu")

	exitCode, _, _ := handler.Execute(context.Background(), common.Upgrade.String(), &common.CommandArgs{})
	if exitCode != 0 {
		t.Errorf("expected exit 0, got %d", exitCode)
	}
	if mockExec.Invoked("rpm") {
		t.Error("apt host must not run rpm")
	}
}

// SLES 12, which the SUSE prefixes accept, ships systemd 228 and so rejects
// --collect. Retrying without it keeps the removal scheduled instead of falling
// back to a synchronous one that tears the agent down mid-command.
func TestSystemHandler_Uninstall_RetriesWithoutCollect(t *testing.T) {
	orig := hasSystemd
	hasSystemd = func() bool { return true }
	t.Cleanup(func() { hasSystemd = orig })

	tests := []struct {
		name            string
		plainScheduleOK bool
		wantSyncRemoval bool
	}{
		{"retry schedules the removal", true, false},
		{"both attempts fail, removal runs synchronously", false, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockExec := common.NewMockCommandExecutor(t)
			mockWS := &MockWSClient{}
			ctxManager := agent.NewContextManager()
			workerPool := pool.NewPool(2, 10)
			defer func() { _ = workerPool.Shutdown(1 * time.Second) }()
			defer ctxManager.Shutdown()

			handler := NewSystemHandler(mockExec, mockWS, ctxManager, workerPool, newMockVersionResolver(), nil)
			handler.uninstallDelay = time.Millisecond
			handler.uninstallDone = make(chan struct{})
			setPackageManagerAndID(t, utils.PkgZypper, "sles")

			schedule := "--uid=0 --gid=0 --unit=alpamon-uninstall --timer-property=OnActiveSec=5 --timer-property=AccuracySec=1s --description=Alpamon Uninstall Service /bin/sh -c zypper --non-interactive remove alpamon; systemctl reset-failed alpamon-uninstall.service 2>/dev/null || true; systemctl reset-failed alpamon-uninstall.timer 2>/dev/null || true"
			mockExec.SetResult("systemd-run --collect "+schedule, 1, "unrecognized option '--collect'", errors.New("exit status 1"))
			if !tt.plainScheduleOK {
				mockExec.SetResult("systemd-run "+schedule, 1, "failed", errors.New("exit status 1"))
			}

			if _, _, err := handler.Execute(context.Background(), common.ByeBye.String(), &common.CommandArgs{}); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			<-handler.uninstallDone

			var retried, syncRemoval bool
			for _, c := range mockExec.GetExecutedCommands() {
				joined := c.Name + " " + strings.Join(c.Args, " ")
				switch {
				case joined == "systemd-run "+schedule:
					retried = true
				case c.Name == "sh" && strings.Contains(joined, "zypper --non-interactive remove alpamon") &&
					!strings.Contains(joined, "systemd-run"):
					syncRemoval = true
				}
			}
			if !retried {
				t.Errorf("expected a retry without --collect, got %+v", mockExec.GetExecutedCommands())
			}
			if syncRemoval != tt.wantSyncRemoval {
				t.Errorf("synchronous removal = %v, want %v", syncRemoval, tt.wantSyncRemoval)
			}
		})
	}
}

// zypper's own output does not name the missing subscription or repository that
// produced these codes, and the console shows the operator nothing else.
func TestWithZypperHint(t *testing.T) {
	tests := []struct {
		name       string
		pkgManager string
		exitCode   int
		wantHint   string
	}{
		{"unreachable repo", utils.PkgZypper, 4, "zypper lr --uri"},
		{"no repositories", utils.PkgZypper, 6, "SUSEConnect --status"},
		{"package in no repository", utils.PkgZypper, 104, "zypper addrepo"},
		{"lock never cleared", utils.PkgZypper, 7, "zypper ps"},
		{"skipped repo that was not tolerated", utils.PkgZypper, 106, "zypper refresh"},
		{"success is left alone", utils.PkgZypper, 0, ""},
		{"other failures are left alone", utils.PkgZypper, 8, ""},
		{"yum is left alone", utils.PkgYum, 6, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setPackageManagerAndID(t, tt.pkgManager, "opensuse-leap")

			got := withZypperHint(tt.exitCode, "zypper said something")
			if tt.wantHint == "" {
				if got != "zypper said something" {
					t.Errorf("expected the output untouched, got %q", got)
				}
				return
			}
			if !strings.Contains(got, tt.wantHint) {
				t.Errorf("expected a hint mentioning %q, got %q", tt.wantHint, got)
			}
			if !strings.HasPrefix(got, "zypper said something") {
				t.Errorf("the hint must follow zypper's own output, got %q", got)
			}
		})
	}
}

// The refresh runs before the update and returns on its own, so its failures need
// the hint too.
func TestSystemHandler_Upgrade_ZypperRefreshFailureCarriesTheHint(t *testing.T) {
	mockExec := common.NewMockCommandExecutor(t)
	mockWS := &MockWSClient{}
	ctxManager := agent.NewContextManager()
	workerPool := pool.NewPool(2, 10)
	defer func() { _ = workerPool.Shutdown(1 * time.Second) }()
	defer ctxManager.Shutdown()

	mockVersions := &MockVersionResolver{LatestVersion: "v9.9.9", PamVersion: ""}
	handler := NewSystemHandler(mockExec, mockWS, ctxManager, workerPool, mockVersions, nil)
	setPackageManagerAndID(t, utils.PkgZypper, "sles")
	mockExec.SetResult("zypper --non-interactive refresh", 6, "No repositories defined.", errors.New("exit status 6"))

	exitCode, output, _ := handler.Execute(context.Background(), common.Upgrade.String(), &common.CommandArgs{})
	if exitCode != 6 {
		t.Fatalf("expected exit 6, got %d", exitCode)
	}
	if !strings.Contains(output, "SUSEConnect --status") {
		t.Errorf("expected the subscription hint, got %q", output)
	}
}
