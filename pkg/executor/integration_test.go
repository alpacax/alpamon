package executor

import (
	"context"
	"os/user"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alpacax/alpamon/v2/internal/pool"
	"github.com/alpacax/alpamon/v2/pkg/agent"
	"github.com/alpacax/alpamon/v2/pkg/executor/handlers/common"
	"github.com/alpacax/alpamon/v2/pkg/executor/handlers/file"
	"github.com/alpacax/alpamon/v2/pkg/executor/handlers/shell"
	"github.com/alpacax/alpamon/v2/pkg/executor/handlers/terminal"
	"github.com/alpacax/alpamon/v2/pkg/executor/handlers/tunnel"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
	err := registry.Register(handler1)
	require.NoError(t, err, "failed to register handler1")
	err = registry.Register(handler2)
	require.NoError(t, err, "failed to register handler2")

	// Verify all commands are accessible
	for _, cmd := range []string{"cmd1", "cmd2", "cmd3", "cmd4"} {
		assert.True(t, registry.IsCommandRegistered(cmd), "command %q should be registered", cmd)
	}

	// Get handlers and verify names
	h1, err := registry.Get("cmd1")
	require.NoError(t, err, "failed to get handler for cmd1")
	assert.Equal(t, "handler1", h1.Name())

	h2, err := registry.Get("cmd3")
	require.NoError(t, err, "failed to get handler for cmd3")
	assert.Equal(t, "handler2", h2.Name())
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
	require.NoError(t, err, "failed to get handler")

	ctx := context.Background()
	args := &common.CommandArgs{}

	// Validate first
	err = h.Validate("test_cmd", args)
	require.NoError(t, err, "validation failed")

	// Execute
	exitCode, output, err := h.Execute(ctx, "test_cmd", args)
	require.NoError(t, err, "execution failed")
	assert.Equal(t, 0, exitCode, "expected exit code 0")
	assert.NotEmpty(t, output, "expected non-empty output")

	// Verify counts
	assert.Equal(t, 1, handler.GetExecuteCount(), "expected execute count 1")
	assert.Equal(t, 1, handler.GetValidateCount(), "expected validate count 1")
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

	assert.Error(t, err, "expected context cancellation error")
	assert.Equal(t, 1, exitCode, "expected exit code 1 on cancellation")
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

	for range concurrency {
		wg.Go(func() {
			_, _, _ = h.Execute(ctx, "concurrent_cmd", args)
		})
	}

	wg.Wait()

	assert.Equal(t, concurrency, handler.GetExecuteCount(), "expected %d executions", concurrency)
}

// TestIntegration_PoolWithRegistry tests pool integration with registry
func TestIntegration_PoolWithRegistry(t *testing.T) {
	workerPool := pool.NewPool(5, 100)
	defer func() { _ = workerPool.Shutdown(5 * time.Second) }()

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

	for range taskCount {
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
	assert.GreaterOrEqual(t, handler.GetExecuteCount(), taskCount/2, "expected at least %d executions", taskCount/2)
}

func TestE2E_ShellChain_GivenParentCtxCancelledMidSegment_ThenExitCodeOneAndLaterSegmentSkipped(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("execs the POSIX sleep binary")
	}

	handler := shell.NewShellHandler(NewExecutor())
	username, groupname := currentIntegrationUser(t)

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(100 * time.Millisecond)
		cancel()
	}()

	args := &common.CommandArgs{
		Command:   "sleep 5 && echo after",
		Username:  username,
		Groupname: groupname,
	}

	exitCode, output, _ := handler.Execute(ctx, common.ShellCmd.String(), args)

	assert.Equal(t, 1, exitCode)
	assert.NotContains(t, output, "after")
}

// executeWithOperators used to give each `&&`/`||`/`;` segment its own fresh
// timeout, letting a 3-segment chain run 3x the nominal timeout.
func TestE2E_ShellOperatorChain_TimeoutCapsWholeChainNotEachSegment(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("execs the POSIX sleep binary")
	}

	handler := shell.NewShellHandler(NewExecutor())
	username, groupname := currentIntegrationUser(t)

	const timeout = 1500 * time.Millisecond
	args := &common.CommandArgs{
		Command:   "sleep 1 && sleep 1 && sleep 1",
		Username:  username,
		Groupname: groupname,
		Timeout:   timeout,
	}

	start := time.Now()
	exitCode, _, _ := handler.Execute(context.Background(), common.ShellCmd.String(), args)
	elapsed := time.Since(start)

	assert.Equal(t, common.TimeoutExitCode, exitCode, "chain should be killed at the chain's own deadline")
	assert.Less(t, elapsed, 2500*time.Millisecond, "the whole chain should be capped at ~one timeout, not restarted per segment")
}

// Given a chain whose second segment is killed mid-run by the chain deadline, then the output
// carries exactly one banner, naming the chain timeout rather than the segment's own elapsed.
func TestE2E_ShellOperatorChain_TimeoutBannerReportsChainTimeoutNotSegmentElapsed(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("execs the POSIX sleep binary")
	}

	handler := shell.NewShellHandler(NewExecutor())
	username, groupname := currentIntegrationUser(t)

	const timeout = 2 * time.Second
	args := &common.CommandArgs{
		Command:   "sleep 1 && sleep 5",
		Username:  username,
		Groupname: groupname,
		Timeout:   timeout,
	}

	exitCode, output, _ := handler.Execute(context.Background(), common.ShellCmd.String(), args)

	require.Equal(t, common.TimeoutExitCode, exitCode)
	assert.Equal(t, 1, strings.Count(output, "Command timed out after"), "exactly one timeout banner, output: %q", output)
	assert.Contains(t, output, "Command timed out after 2s")
	assert.NotContains(t, output, "Command timed out after 1s")
}

// Given a chain whose first segment consumes the whole deadline via timeout
// under ";", when the chain times out, then the skipped second segment does
// not leave the chain without any banner at all.
func TestE2E_ShellOperatorChain_TimeoutBannerPresentEvenWhenNextSegmentSkipped(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("execs the POSIX sleep binary")
	}

	handler := shell.NewShellHandler(NewExecutor())
	username, groupname := currentIntegrationUser(t)

	const timeout = 1 * time.Second
	args := &common.CommandArgs{
		Command:   "sleep 3 ; echo done",
		Username:  username,
		Groupname: groupname,
		Timeout:   timeout,
	}

	exitCode, output, _ := handler.Execute(context.Background(), common.ShellCmd.String(), args)

	require.Equal(t, common.TimeoutExitCode, exitCode)
	assert.Equal(t, 1, strings.Count(output, "Command timed out after"), "exactly one timeout banner, output: %q", output)
	assert.Contains(t, output, "Command timed out after 1s")
	assert.NotContains(t, output, "done")
}

func currentIntegrationUser(t *testing.T) (string, string) {
	t.Helper()
	usr, err := user.Current()
	require.NoError(t, err)
	grp, err := user.LookupGroupId(usr.Gid)
	require.NoError(t, err)
	return usr.Username, grp.Name
}

func TestDispatcherReportsMissingGroup(t *testing.T) {
	for _, tt := range []struct {
		command string
		args    common.CommandArgs
	}{
		{command: "shell", args: common.CommandArgs{Command: "echo hi", Username: "account"}},
		{command: "opentunnel", args: common.CommandArgs{SessionID: "editor-group", URL: "wss://example.com", ClientType: "editor", Username: "account"}},
		{command: "openftp", args: common.CommandArgs{SessionID: "ftp-group", URL: "wss://example.com", Username: "account"}},
		{command: "upload", args: common.CommandArgs{Username: "account", Paths: []string{"unused"}}},
	} {
		t.Run(tt.command, func(t *testing.T) {
			if tt.command == "opentunnel" && runtime.GOOS != "linux" {
				t.Skip("editor group validation applies on Linux")
			}
			mock := common.NewMockCommandExecutor(t)
			dispatcher := NewCommandDispatcher(nil, nil)
			for _, handler := range []common.Handler{
				shell.NewShellHandler(mock), file.NewFileHandler(mock, nil),
				terminal.NewTerminalHandler(mock, nil, nil), tunnel.NewTunnelHandler(mock),
			} {
				require.NoError(t, dispatcher.RegisterHandler(handler))
			}
			var chunks []string
			if tt.command == "shell" {
				tt.args.ChunkCallback = func(_ context.Context, content string) { chunks = append(chunks, content) }
			}
			code, output, _ := dispatcher.Execute(t.Context(), tt.command, &tt.args)
			assert.Equal(t, 1, code)
			assert.Contains(t, output, "groupname is required")
			assert.Empty(t, mock.GetExecutedCommands())
			if tt.command == "shell" {
				assert.Equal(t, []string{"alpamon: groupname is required\n"}, chunks)
			}
		})
	}
}
