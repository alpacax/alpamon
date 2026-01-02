package shell

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/alpacax/alpamon/pkg/executor/handlers/common"
	"github.com/rs/zerolog/log"
)

// ShellHandler handles shell command execution
type ShellHandler struct {
	*common.BaseHandler
}

// NewShellHandler creates a new shell handler
func NewShellHandler(cmdExecutor common.CommandExecutor) *ShellHandler {
	h := &ShellHandler{
		BaseHandler: common.NewBaseHandler(
			common.Shell,
			[]common.CommandType{
				common.ShellCmd,
				common.Exec,
			},
			cmdExecutor,
		),
	}
	return h
}

// Execute runs the shell command
func (h *ShellHandler) Execute(ctx context.Context, cmd string, args *common.CommandArgs) (int, string, error) {
	switch cmd {
	case common.ShellCmd.String(), common.Exec.String():
		return h.handleShellCommand(ctx, args)
	default:
		return 1, "", fmt.Errorf("unknown shell command: %s", cmd)
	}
}

// Validate checks if the arguments are valid for the command
func (h *ShellHandler) Validate(cmd string, args *common.CommandArgs) error {
	if args.Command == "" {
		return fmt.Errorf("shell command is required")
	}
	return nil
}

// handleShellCommand executes a shell command with support for operators (&&, ||, ;)
func (h *ShellHandler) handleShellCommand(ctx context.Context, args *common.CommandArgs) (int, string, error) {
	command := args.Command
	username := args.Username
	if username == "" {
		username = "root"
	}
	groupname := args.Groupname
	if groupname == "" {
		groupname = username
	}

	// Get environment variables
	env := args.Env

	// Get timeout
	timeout := int(args.Timeout.Seconds())

	log.Debug().
		Str("command", command).
		Str("user", username).
		Str("group", groupname).
		Int("timeout", timeout).
		Msg("Executing shell command")

	// Parse and execute command with operators support
	return h.executeWithOperators(ctx, command, username, groupname, env, timeout)
}

// executeWithOperators handles shell operators (&&, ||, ;)
func (h *ShellHandler) executeWithOperators(ctx context.Context, command, username, groupname string, env map[string]string, timeoutSecs int) (int, string, error) {
	spl := strings.Fields(command)
	var currentCmd []string
	var results strings.Builder
	var exitCode int
	var result string

	timeout := time.Duration(timeoutSecs) * time.Second
	if timeout == 0 {
		timeout = 120 * time.Second // Default timeout
	}

	for _, arg := range spl {
		switch arg {
		case "&&":
			// Execute current command
			if len(currentCmd) > 0 {
				exitCode, result = h.executeCommand(ctx, currentCmd, username, groupname, env, timeout)
				results.WriteString(result)
				// Stop if command fails
				if exitCode != 0 {
					return exitCode, results.String(), nil
				}
				currentCmd = nil
			}
		case "||":
			// Execute current command
			if len(currentCmd) > 0 {
				exitCode, result = h.executeCommand(ctx, currentCmd, username, groupname, env, timeout)
				results.WriteString(result)
				// Continue only if command fails
				if exitCode == 0 {
					return exitCode, results.String(), nil
				}
				currentCmd = nil
			}
		case ";":
			// Execute current command
			if len(currentCmd) > 0 {
				exitCode, result = h.executeCommand(ctx, currentCmd, username, groupname, env, timeout)
				results.WriteString(result)
				// Continue regardless of result
				currentCmd = nil
			}
		default:
			currentCmd = append(currentCmd, arg)
		}
	}

	// Execute any remaining command
	if len(currentCmd) > 0 {
		exitCode, result = h.executeCommand(ctx, currentCmd, username, groupname, env, timeout)
		results.WriteString(result)
	}

	return exitCode, results.String(), nil
}

// executeCommand executes a single command
func (h *ShellHandler) executeCommand(ctx context.Context, cmdArgs []string, username, groupname string, env map[string]string, timeout time.Duration) (int, string) {
	if len(cmdArgs) == 0 {
		return 0, ""
	}

	// Execute command through the executor with full parameters (user, group, env, timeout)
	exitCode, output, err := h.Executor.Exec(ctx, cmdArgs, username, groupname, env, timeout)

	if err != nil && exitCode == -1 {
		// Command execution error (not just non-zero exit)
		return exitCode, err.Error()
	}

	return exitCode, output
}
