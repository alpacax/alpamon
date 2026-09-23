package shell

import (
	"context"
	"errors"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/alpacax/alpamon/v2/pkg/executor/handlers/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// executedUsers lists the user each executed command ran as, so a test can
// assert on the whole set and see every actual user when the check fails.
func executedUsers(mock *common.MockCommandExecutor) []string {
	cmds := mock.GetExecutedCommands()
	users := make([]string, 0, len(cmds))
	for _, cmd := range cmds {
		users = append(users, cmd.User)
	}
	return users
}

func TestShellHandler_Name(t *testing.T) {
	mockExec := common.NewMockCommandExecutor(t)
	handler := NewShellHandler(mockExec)
	assert.Equal(t, common.Shell.String(), handler.Name())
}

func TestShellHandler_Commands(t *testing.T) {
	mockExec := common.NewMockCommandExecutor(t)
	handler := NewShellHandler(mockExec)

	assert.Equal(t, []string{
		common.ShellCmd.String(),
		common.Exec.String(),
		common.ExecFile.String(),
	}, handler.Commands())
}

func TestShellHandler_Execute_Basic(t *testing.T) {
	mockExec := common.NewMockCommandExecutor(t)
	// Key format is "name arg1 arg2..." - for single word command it's just "ls"
	mockExec.SetResult("ls", 0, "file1.txt\nfile2.txt", nil)
	handler := NewShellHandler(mockExec)
	ctx := context.Background()

	args := &common.CommandArgs{
		Command: "ls",
	}

	exitCode, output, err := handler.Execute(ctx, common.ShellCmd.String(), args)

	require.NoError(t, err)
	assert.Equal(t, 0, exitCode)
	assert.Contains(t, output, "file1.txt")
}

func TestShellHandler_Execute_Exec(t *testing.T) {
	mockExec := common.NewMockCommandExecutor(t)
	mockExec.SetResult("echo hello", 0, "hello", nil)
	handler := NewShellHandler(mockExec)
	ctx := context.Background()

	args := &common.CommandArgs{
		Command: "echo hello",
	}

	exitCode, output, err := handler.Execute(ctx, common.Exec.String(), args)

	require.NoError(t, err)
	assert.Equal(t, 0, exitCode)
	assert.Contains(t, output, "hello")
}

func TestShellHandler_Execute_AndOperator(t *testing.T) {
	mockExec := common.NewMockCommandExecutor(t)
	// Shell handler uses strings.Fields which splits "cmd1 && cmd2" into ["cmd1", "&&", "cmd2"]
	mockExec.SetResult("cmd1", 0, "output1", nil)
	mockExec.SetResult("cmd2", 0, "output2", nil)
	handler := NewShellHandler(mockExec)
	ctx := context.Background()

	args := &common.CommandArgs{
		Command: "cmd1 && cmd2",
	}

	exitCode, output, err := handler.Execute(ctx, common.ShellCmd.String(), args)

	require.NoError(t, err)
	assert.Equal(t, 0, exitCode)
	assert.Contains(t, output, "output1")
	assert.Contains(t, output, "output2")
}

func TestShellHandler_AndStopsOnFailure(t *testing.T) {
	mockExec := common.NewMockCommandExecutor(t)
	mockExec.SetResult("cmd1", 1, "error output", nil) // First command fails
	mockExec.SetResult("cmd2", 0, "output2", nil)
	handler := NewShellHandler(mockExec)
	ctx := context.Background()

	args := &common.CommandArgs{
		Command: "cmd1 && cmd2",
	}

	exitCode, _, err := handler.Execute(ctx, common.ShellCmd.String(), args)

	require.NoError(t, err)
	assert.Equal(t, 1, exitCode)
}

func TestShellHandler_Execute_OrOperator(t *testing.T) {
	mockExec := common.NewMockCommandExecutor(t)
	mockExec.SetResult("cmd1", 1, "error", nil) // First fails
	mockExec.SetResult("cmd2", 0, "success", nil)
	handler := NewShellHandler(mockExec)
	ctx := context.Background()

	args := &common.CommandArgs{
		Command: "cmd1 || cmd2",
	}

	exitCode, output, err := handler.Execute(ctx, common.ShellCmd.String(), args)

	require.NoError(t, err)
	assert.Equal(t, 0, exitCode)
	assert.Contains(t, output, "success")
}

func TestShellHandler_OrStopsOnSuccess(t *testing.T) {
	mockExec := common.NewMockCommandExecutor(t)
	mockExec.SetResult("cmd1", 0, "success", nil) // First succeeds
	mockExec.SetResult("cmd2", 0, "output2", nil)
	handler := NewShellHandler(mockExec)
	ctx := context.Background()

	args := &common.CommandArgs{
		Command: "cmd1 || cmd2",
	}

	exitCode, output, err := handler.Execute(ctx, common.ShellCmd.String(), args)

	require.NoError(t, err)
	assert.Equal(t, 0, exitCode)
	// Only cmd1's output should be present (cmd2 shouldn't run)
	assert.Contains(t, output, "success")
	assert.NotContains(t, output, "output2")
}

func TestShellHandler_Execute_Semicolon(t *testing.T) {
	mockExec := common.NewMockCommandExecutor(t)
	mockExec.SetResult("cmd1", 1, "error", nil) // First fails
	mockExec.SetResult("cmd2", 0, "success", nil)
	handler := NewShellHandler(mockExec)
	ctx := context.Background()

	args := &common.CommandArgs{
		Command: "cmd1 ; cmd2",
	}

	exitCode, output, err := handler.Execute(ctx, common.ShellCmd.String(), args)

	require.NoError(t, err)
	// Last command exit code
	assert.Equal(t, 0, exitCode, "the exit code must come from cmd2")
	// Both outputs should be present
	assert.Contains(t, output, "error")
	assert.Contains(t, output, "success")
}

func TestShellHandler_CustomUser(t *testing.T) {
	mockExec := common.NewMockCommandExecutor(t)
	mockExec.SetResult("whoami", 0, "testuser", nil)
	handler := NewShellHandler(mockExec)
	ctx := context.Background()

	args := &common.CommandArgs{
		Command:  "whoami",
		Username: "testuser",
	}

	exitCode, _, err := handler.Execute(ctx, common.ShellCmd.String(), args)

	require.NoError(t, err)
	assert.Equal(t, 0, exitCode)

	// Exec method adds to commands, then calls Run which also adds
	// So we check that at least one command has the right user
	assert.Contains(t, executedUsers(mockExec), "testuser")
}

func TestShellHandler_DefaultUser(t *testing.T) {
	mockExec := common.NewMockCommandExecutor(t)
	mockExec.SetResult("whoami", 0, "root", nil)
	handler := NewShellHandler(mockExec)
	ctx := context.Background()

	args := &common.CommandArgs{
		Command: "whoami",
		// Username not set - should default to "root"
	}

	_, _, err := handler.Execute(ctx, common.ShellCmd.String(), args)

	require.NoError(t, err)
	assert.Contains(t, executedUsers(mockExec), "root")
}

func TestShellHandler_WithTimeout(t *testing.T) {
	mockExec := common.NewMockCommandExecutor(t)
	mockExec.SetResult("sleep 1", 0, "", nil)
	handler := NewShellHandler(mockExec)
	ctx := context.Background()

	args := &common.CommandArgs{
		Command: "sleep 1",
		Timeout: 10 * time.Second,
	}

	exitCode, _, err := handler.Execute(ctx, common.ShellCmd.String(), args)

	require.NoError(t, err)
	assert.Equal(t, 0, exitCode)
}

func TestShellHandler_GivenNoTimeout_WhenExecuted_ThenChainDeadlineIsThirtyMinutes(t *testing.T) {
	mockExec := common.NewMockCommandExecutor(t)
	mockExec.SetResult("ls", 0, "output", nil)
	handler := NewShellHandler(mockExec)
	ctx := context.Background()

	var capturedCtx context.Context
	args := &common.CommandArgs{
		Command: "ls",
		// Timeout not set - should default to 30 minutes
		ChunkCallback: func(cbCtx context.Context, content string) {
			capturedCtx = cbCtx
		},
	}

	before := time.Now()
	exitCode, _, err := handler.Execute(ctx, common.ShellCmd.String(), args)

	require.NoError(t, err)
	assert.Equal(t, 0, exitCode)

	cmds := mockExec.GetExecutedCommands()
	require.NotEmpty(t, cmds, "expected at least one executed command")
	assert.Equal(t, time.Duration(0), cmds[0].Timeout)

	require.NotNil(t, capturedCtx, "expected chunk callback to be invoked with a ctx")
	deadline, ok := capturedCtx.Deadline()
	require.True(t, ok, "expected the chain ctx to carry a deadline")
	assert.WithinDuration(t, before.Add(30*time.Minute), deadline, 5*time.Second)
}

func TestShellHandler_Validate_Empty(t *testing.T) {
	mockExec := common.NewMockCommandExecutor(t)
	handler := NewShellHandler(mockExec)

	args := &common.CommandArgs{
		Command: "", // Empty command
	}

	err := handler.Validate(common.ShellCmd.String(), args)

	assert.ErrorContains(t, err, "required")
}

func TestShellHandler_Validate_Valid(t *testing.T) {
	mockExec := common.NewMockCommandExecutor(t)
	handler := NewShellHandler(mockExec)

	args := &common.CommandArgs{
		Command: "ls -la",
	}

	err := handler.Validate(common.ShellCmd.String(), args)

	assert.NoError(t, err)
}

func TestShellHandler_UnknownCommand(t *testing.T) {
	mockExec := common.NewMockCommandExecutor(t)
	handler := NewShellHandler(mockExec)
	ctx := context.Background()

	args := &common.CommandArgs{
		Command: "ls",
	}

	exitCode, _, err := handler.Execute(ctx, "unknown_command", args)

	assert.Equal(t, 1, exitCode)
	assert.ErrorContains(t, err, "unknown shell command")
}

func TestShellHandler_CommandExecutionError(t *testing.T) {
	mockExec := common.NewMockCommandExecutor(t)
	// Executor folds cmd.Start failures into output; mock mirrors that.
	mockExec.SetResult("failing_cmd", 1, "command not found", errors.New("command not found"))
	handler := NewShellHandler(mockExec)
	ctx := context.Background()

	args := &common.CommandArgs{
		Command: "failing_cmd",
	}

	exitCode, output, err := handler.Execute(ctx, common.ShellCmd.String(), args)

	require.NoError(t, err, "the executor error must be folded into the output, not returned")
	assert.Equal(t, 1, exitCode)
	assert.Contains(t, output, "not found")
}

func TestShellHandler_WithEnv(t *testing.T) {
	mockExec := common.NewMockCommandExecutor(t)
	mockExec.SetResult("printenv", 0, "TEST_VAR=test_value", nil)
	handler := NewShellHandler(mockExec)
	ctx := context.Background()

	args := &common.CommandArgs{
		Command: "printenv",
		Env: map[string]string{
			"TEST_VAR": "test_value",
		},
	}

	exitCode, _, err := handler.Execute(ctx, common.ShellCmd.String(), args)

	require.NoError(t, err)
	assert.Equal(t, 0, exitCode)
}

func TestShellHandler_MixedOperators(t *testing.T) {
	mockExec := common.NewMockCommandExecutor(t)
	mockExec.SetResult("cmd1", 0, "out1", nil)
	mockExec.SetResult("cmd2", 1, "err2", nil)
	mockExec.SetResult("cmd3", 0, "out3", nil)
	handler := NewShellHandler(mockExec)
	ctx := context.Background()

	// cmd1 && cmd2 || cmd3
	// cmd1 succeeds (0), run cmd2
	// cmd2 fails (1), run cmd3 (due to ||)
	args := &common.CommandArgs{
		Command: "cmd1 && cmd2 || cmd3",
	}

	exitCode, output, err := handler.Execute(ctx, common.ShellCmd.String(), args)

	require.NoError(t, err)
	assert.Equal(t, 0, exitCode)
	// cmd1's output should be present
	assert.Contains(t, output, "out1")
}

func TestShellHandler_AllowSh(t *testing.T) {
	if runtime.GOOS == "windows" {
		// On Windows, handleShellCommand routes AllowSh=true through
		// powershell with different args. This unit test locks in the
		// Unix /bin/sh -c contract; the Windows path is exercised by
		// integration tests.
		t.Skip("AllowSh=true uses powershell on Windows; /bin/sh contract is Unix-only.")
	}
	mockExec := common.NewMockCommandExecutor(t)
	// When AllowSh is true, handler calls /bin/sh -c <command>
	// Mock key: "/bin/sh" + " " + "-c" + " " + "grep err /log | head"
	mockExec.SetResult("/bin/sh -c grep err /log | head", 0, "error line 1", nil)
	handler := NewShellHandler(mockExec)
	ctx := context.Background()

	args := &common.CommandArgs{
		Command: "grep err /log | head",
		AllowSh: true,
	}

	exitCode, output, err := handler.Execute(ctx, common.ShellCmd.String(), args)

	require.NoError(t, err)
	assert.Equal(t, 0, exitCode)
	assert.Contains(t, output, "error line 1")

	// Verify it was called via /bin/sh -c, not split by Fields
	cmds := mockExec.GetExecutedCommands()
	require.NotEmpty(t, cmds, "expected at least one executed command")
	assert.Equal(t, "/bin/sh", cmds[0].Name)
	assert.Equal(t, []string{"-c", "grep err /log | head"}, cmds[0].Args)
}

func TestShellHandler_AllowSh_False_UsesDirectExec(t *testing.T) {
	mockExec := common.NewMockCommandExecutor(t)
	// Without AllowSh, "echo hello" is split by Fields into ["echo", "hello"]
	mockExec.SetResult("echo hello", 0, "hello", nil)
	handler := NewShellHandler(mockExec)
	ctx := context.Background()

	args := &common.CommandArgs{
		Command: "echo hello",
		AllowSh: false,
	}

	exitCode, _, err := handler.Execute(ctx, common.ShellCmd.String(), args)

	require.NoError(t, err)
	assert.Equal(t, 0, exitCode)

	// Verify it was NOT called via /bin/sh
	cmds := mockExec.GetExecutedCommands()
	require.NotEmpty(t, cmds, "expected at least one executed command")
	assert.NotEqual(t, "/bin/sh", cmds[0].Name, "expected direct exec, not /bin/sh")
}

func TestShellHandler_MultiWordCommand(t *testing.T) {
	mockExec := common.NewMockCommandExecutor(t)
	// "ls -la /tmp" -> Fields splits to ["ls", "-la", "/tmp"]
	// Exec is called with args[0]="ls", args[1:]=["-la", "/tmp"]
	// Run key is "ls -la /tmp"
	mockExec.SetResult("ls -la /tmp", 0, "total 0", nil)
	handler := NewShellHandler(mockExec)
	ctx := context.Background()

	args := &common.CommandArgs{
		Command: "ls -la /tmp",
	}

	exitCode, output, err := handler.Execute(ctx, common.ShellCmd.String(), args)

	require.NoError(t, err)
	assert.Equal(t, 0, exitCode)
	assert.Contains(t, output, "total")
}

func TestExecuteWithOperators_GivenExpiredDeadline_WhenChainRuns_ThenReportsTimeout(t *testing.T) {
	mockExec := common.NewMockCommandExecutor(t)
	mockExec.SetResult("echo a", 0, "a", nil)
	mockExec.SetResult("echo b", 0, "b", nil)
	handler := NewShellHandler(mockExec)

	parentCtx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()

	args := &common.CommandArgs{
		Command: "echo a && echo b",
		AllowSh: false,
	}

	exitCode, output, err := handler.Execute(parentCtx, common.ShellCmd.String(), args)

	require.NoError(t, err)
	assert.Equal(t, common.TimeoutExitCode, exitCode)
	assert.Equal(t, 1, strings.Count(output, "Command timed out after"))
	assert.Empty(t, mockExec.GetExecutedCommands())
}

func TestExecuteWithOperators_GivenCancelledParent_WhenChainRuns_ThenStopsWithoutTimeoutBanner(t *testing.T) {
	mockExec := common.NewMockCommandExecutor(t)
	mockExec.SetResult("echo a", 0, "a", nil)
	mockExec.SetResult("echo b", 0, "b", nil)
	handler := NewShellHandler(mockExec)

	parentCtx, cancel := context.WithCancel(context.Background())
	cancel()

	args := &common.CommandArgs{
		Command: "echo a ; echo b",
		AllowSh: false,
	}

	exitCode, output, err := handler.Execute(parentCtx, common.ShellCmd.String(), args)

	require.NoError(t, err)
	assert.Equal(t, 0, strings.Count(output, "timed out"))
	assert.NotEqual(t, common.TimeoutExitCode, exitCode)
	assert.Empty(t, mockExec.GetExecutedCommands())
}

// cancelAfterFirstExec wraps MockCommandExecutor and cancels the given
// cancel func right after the first ExecWithStreamingHook call returns, so
// tests can simulate the parent ctx being cancelled between segments.
type cancelAfterFirstExec struct {
	*common.MockCommandExecutor
	cancel context.CancelFunc
	calls  int
}

func (c *cancelAfterFirstExec) ExecWithStreamingHook(ctx context.Context, args []string, username, groupname string, env map[string]string, timeout time.Duration, pidHook func(pid int), chunkCallback func(ctx context.Context, content string)) (int, string, error) {
	c.calls++
	code, out, err := c.MockCommandExecutor.ExecWithStreamingHook(ctx, args, username, groupname, env, timeout, pidHook, chunkCallback)
	c.cancel()
	return code, out, err
}

func TestExecuteWithOperators_GivenParentCancelledMidChain_WhenTailSegmentSkipped_ThenReportsFailureAndNeverRunsIt(t *testing.T) {
	mockExec := common.NewMockCommandExecutor(t)
	mockExec.SetResult("echo a", 0, "a", nil)
	mockExec.SetResult("echo b", 0, "b", nil)

	parentCtx, cancel := context.WithCancel(context.Background())
	wrapped := &cancelAfterFirstExec{MockCommandExecutor: mockExec, cancel: cancel}
	handler := NewShellHandler(wrapped)

	args := &common.CommandArgs{
		Command: "echo a && echo b",
		AllowSh: false,
	}

	exitCode, output, err := handler.Execute(parentCtx, common.ShellCmd.String(), args)

	require.NoError(t, err)
	assert.Equal(t, 1, exitCode)
	assert.Equal(t, 0, strings.Count(output, "timed out"))
	assert.Equal(t, 1, wrapped.calls)
}

func TestExecuteWithOperators_GivenParentCancelledMidChain_WhenMidSegmentSkipped_ThenReportsFailureAndNeverRunsRemainder(t *testing.T) {
	mockExec := common.NewMockCommandExecutor(t)
	mockExec.SetResult("echo a", 0, "a", nil)
	mockExec.SetResult("echo b", 0, "b", nil)
	mockExec.SetResult("echo c", 0, "c", nil)

	parentCtx, cancel := context.WithCancel(context.Background())
	wrapped := &cancelAfterFirstExec{MockCommandExecutor: mockExec, cancel: cancel}
	handler := NewShellHandler(wrapped)

	args := &common.CommandArgs{
		Command: "echo a && echo b && echo c",
		AllowSh: false,
	}

	exitCode, output, err := handler.Execute(parentCtx, common.ShellCmd.String(), args)

	require.NoError(t, err)
	assert.Equal(t, 1, exitCode)
	assert.Equal(t, 0, strings.Count(output, "timed out"))
	assert.Equal(t, 1, wrapped.calls)
}
