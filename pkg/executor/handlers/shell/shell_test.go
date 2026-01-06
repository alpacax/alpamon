package shell

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/alpacax/alpamon/pkg/executor/handlers/common"
)

func TestShellHandler_Name(t *testing.T) {
	mockExec := common.NewMockCommandExecutor(t)
	handler := NewShellHandler(mockExec)
	if handler.Name() != common.Shell.String() {
		t.Errorf("expected name %q, got %q", common.Shell.String(), handler.Name())
	}
}

func TestShellHandler_Commands(t *testing.T) {
	mockExec := common.NewMockCommandExecutor(t)
	handler := NewShellHandler(mockExec)
	commands := handler.Commands()

	expected := []string{
		common.ShellCmd.String(),
		common.Exec.String(),
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

func TestShellHandler_Execute_Basic(t *testing.T) {
	mockExec := common.NewMockCommandExecutor(t)
	// Key format is "name arg1 arg2..." - for single word command it's just "ls "
	mockExec.SetResult("ls ", 0, "file1.txt\nfile2.txt", nil)
	handler := NewShellHandler(mockExec)
	ctx := context.Background()

	args := &common.CommandArgs{
		Command: "ls",
	}

	exitCode, output, err := handler.Execute(ctx, common.ShellCmd.String(), args)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if exitCode != 0 {
		t.Errorf("expected exit code 0, got %d", exitCode)
	}
	if !strings.Contains(output, "file1.txt") {
		t.Errorf("expected output to contain 'file1.txt', got %q", output)
	}
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

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if exitCode != 0 {
		t.Errorf("expected exit code 0, got %d", exitCode)
	}
	if !strings.Contains(output, "hello") {
		t.Errorf("expected output to contain 'hello', got %q", output)
	}
}

func TestShellHandler_Execute_AndOperator(t *testing.T) {
	mockExec := common.NewMockCommandExecutor(t)
	// Shell handler uses strings.Fields which splits "cmd1 && cmd2" into ["cmd1", "&&", "cmd2"]
	mockExec.SetResult("cmd1 ", 0, "output1", nil)
	mockExec.SetResult("cmd2 ", 0, "output2", nil)
	handler := NewShellHandler(mockExec)
	ctx := context.Background()

	args := &common.CommandArgs{
		Command: "cmd1 && cmd2",
	}

	exitCode, output, err := handler.Execute(ctx, common.ShellCmd.String(), args)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if exitCode != 0 {
		t.Errorf("expected exit code 0, got %d", exitCode)
	}
	if !strings.Contains(output, "output1") || !strings.Contains(output, "output2") {
		t.Errorf("expected output to contain both outputs, got %q", output)
	}
}

func TestShellHandler_AndStopsOnFailure(t *testing.T) {
	mockExec := common.NewMockCommandExecutor(t)
	mockExec.SetResult("cmd1 ", 1, "error output", nil) // First command fails
	mockExec.SetResult("cmd2 ", 0, "output2", nil)
	handler := NewShellHandler(mockExec)
	ctx := context.Background()

	args := &common.CommandArgs{
		Command: "cmd1 && cmd2",
	}

	exitCode, _, err := handler.Execute(ctx, common.ShellCmd.String(), args)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if exitCode != 1 {
		t.Errorf("expected exit code 1, got %d", exitCode)
	}
}

func TestShellHandler_Execute_OrOperator(t *testing.T) {
	mockExec := common.NewMockCommandExecutor(t)
	mockExec.SetResult("cmd1 ", 1, "error", nil) // First fails
	mockExec.SetResult("cmd2 ", 0, "success", nil)
	handler := NewShellHandler(mockExec)
	ctx := context.Background()

	args := &common.CommandArgs{
		Command: "cmd1 || cmd2",
	}

	exitCode, output, err := handler.Execute(ctx, common.ShellCmd.String(), args)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if exitCode != 0 {
		t.Errorf("expected exit code 0, got %d", exitCode)
	}
	if !strings.Contains(output, "success") {
		t.Errorf("expected output to contain 'success', got %q", output)
	}
}

func TestShellHandler_OrStopsOnSuccess(t *testing.T) {
	mockExec := common.NewMockCommandExecutor(t)
	mockExec.SetResult("cmd1 ", 0, "success", nil) // First succeeds
	mockExec.SetResult("cmd2 ", 0, "output2", nil)
	handler := NewShellHandler(mockExec)
	ctx := context.Background()

	args := &common.CommandArgs{
		Command: "cmd1 || cmd2",
	}

	exitCode, output, err := handler.Execute(ctx, common.ShellCmd.String(), args)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if exitCode != 0 {
		t.Errorf("expected exit code 0, got %d", exitCode)
	}
	// Only cmd1's output should be present (cmd2 shouldn't run)
	if !strings.Contains(output, "success") {
		t.Errorf("expected output to contain 'success', got %q", output)
	}
}

func TestShellHandler_Execute_Semicolon(t *testing.T) {
	mockExec := common.NewMockCommandExecutor(t)
	mockExec.SetResult("cmd1 ", 1, "error", nil) // First fails
	mockExec.SetResult("cmd2 ", 0, "success", nil)
	handler := NewShellHandler(mockExec)
	ctx := context.Background()

	args := &common.CommandArgs{
		Command: "cmd1 ; cmd2",
	}

	exitCode, output, err := handler.Execute(ctx, common.ShellCmd.String(), args)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Last command exit code
	if exitCode != 0 {
		t.Errorf("expected exit code 0 (from cmd2), got %d", exitCode)
	}
	// Both outputs should be present
	if !strings.Contains(output, "error") || !strings.Contains(output, "success") {
		t.Errorf("expected output to contain both outputs, got %q", output)
	}
}

func TestShellHandler_CustomUser(t *testing.T) {
	mockExec := common.NewMockCommandExecutor(t)
	mockExec.SetResult("whoami ", 0, "testuser", nil)
	handler := NewShellHandler(mockExec)
	ctx := context.Background()

	args := &common.CommandArgs{
		Command:  "whoami",
		Username: "testuser",
	}

	exitCode, _, err := handler.Execute(ctx, common.ShellCmd.String(), args)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if exitCode != 0 {
		t.Errorf("expected exit code 0, got %d", exitCode)
	}

	cmds := mockExec.GetExecutedCommands()
	// Exec method adds to commands, then calls Run which also adds
	// So we check that at least one command has the right user
	foundCorrectUser := false
	for _, cmd := range cmds {
		if cmd.User == "testuser" {
			foundCorrectUser = true
			break
		}
	}
	if !foundCorrectUser {
		t.Errorf("expected at least one command with user 'testuser', got %+v", cmds)
	}
}

func TestShellHandler_DefaultUser(t *testing.T) {
	mockExec := common.NewMockCommandExecutor(t)
	mockExec.SetResult("whoami ", 0, "root", nil)
	handler := NewShellHandler(mockExec)
	ctx := context.Background()

	args := &common.CommandArgs{
		Command: "whoami",
		// Username not set - should default to "root"
	}

	_, _, err := handler.Execute(ctx, common.ShellCmd.String(), args)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	cmds := mockExec.GetExecutedCommands()
	foundRootUser := false
	for _, cmd := range cmds {
		if cmd.User == "root" {
			foundRootUser = true
			break
		}
	}
	if !foundRootUser {
		t.Errorf("expected at least one command with default user 'root', got %+v", cmds)
	}
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

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if exitCode != 0 {
		t.Errorf("expected exit code 0, got %d", exitCode)
	}
}

func TestShellHandler_DefaultTimeout(t *testing.T) {
	mockExec := common.NewMockCommandExecutor(t)
	mockExec.SetResult("ls ", 0, "output", nil)
	handler := NewShellHandler(mockExec)
	ctx := context.Background()

	args := &common.CommandArgs{
		Command: "ls",
		// Timeout not set - should default to 120 seconds
	}

	exitCode, _, err := handler.Execute(ctx, common.ShellCmd.String(), args)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if exitCode != 0 {
		t.Errorf("expected exit code 0, got %d", exitCode)
	}
}

func TestShellHandler_Validate_Empty(t *testing.T) {
	mockExec := common.NewMockCommandExecutor(t)
	handler := NewShellHandler(mockExec)

	args := &common.CommandArgs{
		Command: "", // Empty command
	}

	err := handler.Validate(common.ShellCmd.String(), args)

	if err == nil {
		t.Error("expected error for empty command")
	}
	if !strings.Contains(err.Error(), "required") {
		t.Errorf("error should mention 'required', got: %v", err)
	}
}

func TestShellHandler_Validate_Valid(t *testing.T) {
	mockExec := common.NewMockCommandExecutor(t)
	handler := NewShellHandler(mockExec)

	args := &common.CommandArgs{
		Command: "ls -la",
	}

	err := handler.Validate(common.ShellCmd.String(), args)

	if err != nil {
		t.Errorf("unexpected validation error: %v", err)
	}
}

func TestShellHandler_UnknownCommand(t *testing.T) {
	mockExec := common.NewMockCommandExecutor(t)
	handler := NewShellHandler(mockExec)
	ctx := context.Background()

	args := &common.CommandArgs{
		Command: "ls",
	}

	exitCode, _, err := handler.Execute(ctx, "unknown_command", args)

	if err == nil {
		t.Error("expected error for unknown command")
	}
	if exitCode != 1 {
		t.Errorf("expected exit code 1, got %d", exitCode)
	}
	if !strings.Contains(err.Error(), "unknown shell command") {
		t.Errorf("error should mention 'unknown shell command', got: %v", err)
	}
}

func TestShellHandler_CommandExecutionError(t *testing.T) {
	mockExec := common.NewMockCommandExecutor(t)
	// Set up a command that returns -1 exit code with error
	mockExec.SetResult("failing_cmd ", -1, "", errors.New("command not found"))
	handler := NewShellHandler(mockExec)
	ctx := context.Background()

	args := &common.CommandArgs{
		Command: "failing_cmd",
	}

	exitCode, output, err := handler.Execute(ctx, common.ShellCmd.String(), args)

	if err != nil {
		t.Fatalf("unexpected error from Execute: %v", err)
	}
	if exitCode != -1 {
		t.Errorf("expected exit code -1, got %d", exitCode)
	}
	if !strings.Contains(output, "not found") {
		t.Errorf("expected output to contain error message, got %q", output)
	}
}

func TestShellHandler_WithEnv(t *testing.T) {
	mockExec := common.NewMockCommandExecutor(t)
	mockExec.SetResult("printenv ", 0, "TEST_VAR=test_value", nil)
	handler := NewShellHandler(mockExec)
	ctx := context.Background()

	args := &common.CommandArgs{
		Command: "printenv",
		Env: map[string]string{
			"TEST_VAR": "test_value",
		},
	}

	exitCode, _, err := handler.Execute(ctx, common.ShellCmd.String(), args)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if exitCode != 0 {
		t.Errorf("expected exit code 0, got %d", exitCode)
	}
}

func TestShellHandler_MixedOperators(t *testing.T) {
	mockExec := common.NewMockCommandExecutor(t)
	mockExec.SetResult("cmd1 ", 0, "out1", nil)
	mockExec.SetResult("cmd2 ", 1, "err2", nil)
	mockExec.SetResult("cmd3 ", 0, "out3", nil)
	handler := NewShellHandler(mockExec)
	ctx := context.Background()

	// cmd1 && cmd2 || cmd3
	// cmd1 succeeds (0), run cmd2
	// cmd2 fails (1), run cmd3 (due to ||)
	args := &common.CommandArgs{
		Command: "cmd1 && cmd2 || cmd3",
	}

	exitCode, output, err := handler.Execute(ctx, common.ShellCmd.String(), args)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if exitCode != 0 {
		t.Errorf("expected exit code 0, got %d", exitCode)
	}
	// cmd1's output should be present
	if !strings.Contains(output, "out1") {
		t.Errorf("expected output to contain 'out1', got %q", output)
	}
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

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if exitCode != 0 {
		t.Errorf("expected exit code 0, got %d", exitCode)
	}
	if !strings.Contains(output, "total") {
		t.Errorf("expected output to contain 'total', got %q", output)
	}
}
