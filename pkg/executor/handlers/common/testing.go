package common

import (
	"context"
	"strings"
	"testing"
	"time"
)

// MockCommandExecutor is a mock implementation of CommandExecutor for testing.
// It is the single source of truth for mocking in this package.
type MockCommandExecutor struct {
	t        *testing.T
	commands []ExecutedCommand
	results  map[string]CommandResult
}

// ExecutedCommand represents a command that was executed by the mock.
type ExecutedCommand struct {
	Name    string
	Args    []string
	User    string
	Timeout time.Duration
}

// CommandResult represents the result of a mocked command execution.
type CommandResult struct {
	ExitCode int
	Output   string
	Err      error
}

func NewMockCommandExecutor(t *testing.T) *MockCommandExecutor {
	return &MockCommandExecutor{
		t:        t,
		commands: []ExecutedCommand{},
		results:  make(map[string]CommandResult),
	}
}

// lookupResult returns the mocked result for a given command key.
func (m *MockCommandExecutor) lookupResult(name string, args ...string) (int, string, error) {
	key := name + " " + strings.Join(args, " ")
	if result, ok := m.results[key]; ok {
		return result.ExitCode, result.Output, result.Err
	}
	return 0, "Mock success", nil
}

func (m *MockCommandExecutor) Run(ctx context.Context, name string, args ...string) (int, string, error) {
	m.commands = append(m.commands, ExecutedCommand{Name: name, Args: args})
	return m.lookupResult(name, args...)
}

func (m *MockCommandExecutor) RunAsUser(ctx context.Context, username string, name string, args ...string) (int, string, error) {
	m.commands = append(m.commands, ExecutedCommand{Name: name, Args: args, User: username})
	return m.lookupResult(name, args...)
}

func (m *MockCommandExecutor) RunWithInput(ctx context.Context, input string, name string, args ...string) (int, string, error) {
	m.commands = append(m.commands, ExecutedCommand{Name: name, Args: args})
	return m.lookupResult(name, args...)
}

func (m *MockCommandExecutor) RunWithTimeout(ctx context.Context, timeout time.Duration, name string, args ...string) (int, string, error) {
	m.commands = append(m.commands, ExecutedCommand{Name: name, Args: args, Timeout: timeout})
	return m.lookupResult(name, args...)
}

func (m *MockCommandExecutor) Exec(ctx context.Context, args []string, username, groupname string, env map[string]string, timeout time.Duration) (int, string, error) {
	if len(args) == 0 {
		return 0, "", nil
	}
	m.commands = append(m.commands, ExecutedCommand{Name: args[0], Args: args[1:], User: username, Timeout: timeout})
	return m.lookupResult(args[0], args[1:]...)
}

func (m *MockCommandExecutor) SetResult(command string, exitCode int, output string, err error) {
	m.results[command] = CommandResult{ExitCode: exitCode, Output: output, Err: err}
}

func (m *MockCommandExecutor) GetExecutedCommands() []ExecutedCommand {
	return m.commands
}
