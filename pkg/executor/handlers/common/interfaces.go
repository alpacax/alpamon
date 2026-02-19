package common

import (
	"context"
	"io"
	"time"
)

// Handler defines the interface for command handlers.
// Each handler is responsible for executing a specific set of commands.
type Handler interface {
	// Name returns the handler name (e.g., "system", "user", "firewall")
	Name() string

	// Commands returns the list of commands this handler supports
	Commands() []string

	// Execute runs the specified command with the given arguments.
	// Returns exit code, output string, and error if command fails.
	Execute(ctx context.Context, cmd string, args *CommandArgs) (exitCode int, output string, err error)

	// Validate checks if the provided arguments are valid for the command.
	// This allows pre-execution validation without running the command.
	Validate(cmd string, args *CommandArgs) error
}

// CommandExecutor defines the interface for executing system commands.
// This interface is defined within the handlers package to avoid circular dependencies.
// The concrete implementation is in the executor package.
type CommandExecutor interface {
	// Run executes a command with the given arguments
	Run(ctx context.Context, name string, args ...string) (int, string, error)

	// RunAsUser executes a command as a specific user
	RunAsUser(ctx context.Context, username string, name string, args ...string) (int, string, error)

	// RunWithInput executes a command with stdin input
	RunWithInput(ctx context.Context, input string, name string, args ...string) (int, string, error)

	// RunWithTimeout executes a command with a timeout
	RunWithTimeout(ctx context.Context, timeout time.Duration, name string, args ...string) (int, string, error)

	// Exec executes a command with all options (user, group, env, timeout)
	Exec(ctx context.Context, args []string, username, groupname string, env map[string]string, timeout time.Duration) (int, string, error)
}

// WSClient interface for WebSocket client operations
type WSClient interface {
	Restart()
	ShutDown()
	RestartCollector()
}

// SystemInfoManager interface for system info operations
type SystemInfoManager interface {
	CommitSystemInfo()
	SyncSystemInfo(keys []string)
}

// APISession interface for API operations (file upload)
type APISession interface {
	MultipartRequest(url string, body io.Reader, contentType string, contentLength int64, timeout time.Duration) ([]byte, int, error)
}
