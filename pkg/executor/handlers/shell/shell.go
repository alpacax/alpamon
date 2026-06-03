package shell

import (
	"context"
	"fmt"
	"runtime"
	"strings"
	"time"

	"github.com/alpacax/alpamon/v2/pkg/executor/handlers/common"
	"github.com/alpacax/alpamon/v2/pkg/runner"
	"github.com/alpacax/alpamon/v2/pkg/utils"
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

	env := args.Env

	timeout := args.Timeout
	if timeout == 0 {
		timeout = common.ShellTimeout
	}

	log.Debug().
		Str("command", command).
		Str("user", username).
		Str("group", groupname).
		Dur("timeout", timeout).
		Bool("allow_sh", args.AllowSh).
		Msg("Executing shell command")

	if args.AllowSh {
		var cmdArgs []string
		if runtime.GOOS == "windows" {
			shell := utils.DefaultShell()
			cmdArgs = append([]string{shell}, utils.DefaultShellArgs()...)
			cmdArgs = append(cmdArgs, "-Command", command)
		} else {
			cmdArgs = []string{"/bin/sh", "-c", command}
		}
		exitCode, result := h.executeCommand(ctx, cmdArgs, username, groupname, env, timeout, args.CommandID, args.ChunkCallback)
		return exitCode, result, nil
	}

	// Fallback: direct execution with manual operator parsing
	return h.executeWithOperators(ctx, command, username, groupname, env, timeout, args.CommandID, args.ChunkCallback)
}

// executeWithOperators handles shell operators (&&, ||, ;). Per-segment output
// (already capped under streaming) is accumulated; under streaming the total is
// capped again so the fin audit copy stays bounded across segments.
func (h *ShellHandler) executeWithOperators(ctx context.Context, command, username, groupname string, env map[string]string, timeout time.Duration, commandID string, chunkCallback func(content string)) (int, string, error) {
	spl := strings.Fields(command)
	var currentCmd []string
	var results strings.Builder
	var exitCode int
	var result string
	streaming := chunkCallback != nil

	appendResult := func(r string) {
		results.WriteString(r)
	}
	finalResult := func() string {
		if streaming {
			return utils.TruncateMiddle(results.String(), utils.AuditOutputCap)
		}
		return results.String()
	}

	for _, arg := range spl {
		switch arg {
		case "&&":
			if len(currentCmd) > 0 {
				exitCode, result = h.executeCommand(ctx, currentCmd, username, groupname, env, timeout, commandID, chunkCallback)
				appendResult(result)
				if exitCode != 0 {
					return exitCode, finalResult(), nil
				}
				currentCmd = nil
			}
		case "||":
			if len(currentCmd) > 0 {
				exitCode, result = h.executeCommand(ctx, currentCmd, username, groupname, env, timeout, commandID, chunkCallback)
				appendResult(result)
				if exitCode == 0 {
					return exitCode, finalResult(), nil
				}
				currentCmd = nil
			}
		case ";":
			if len(currentCmd) > 0 {
				exitCode, result = h.executeCommand(ctx, currentCmd, username, groupname, env, timeout, commandID, chunkCallback)
				appendResult(result)
				currentCmd = nil
			}
		default:
			currentCmd = append(currentCmd, arg)
		}
	}

	if len(currentCmd) > 0 {
		exitCode, result = h.executeCommand(ctx, currentCmd, username, groupname, env, timeout, commandID, chunkCallback)
		appendResult(result)
	}

	return exitCode, finalResult(), nil
}

// executeCommand registers the child pid with the PAM tracker when commandID
// is set so sudo inside the command is authorized by command_id. Execute
// folds startup errors into output, so the err return is intentionally
// dropped here.
func (h *ShellHandler) executeCommand(ctx context.Context, cmdArgs []string, username, groupname string, env map[string]string, timeout time.Duration, commandID string, chunkCallback func(content string)) (int, string) {
	if len(cmdArgs) == 0 {
		return 0, ""
	}

	var pidHook func(pid int)
	var cleanup func()
	if commandID != "" {
		pidHook = func(pid int) {
			cleanup = runner.RegisterCommandPID(pid, commandID, username)
		}
	}
	exitCode, output, _ := h.Executor.ExecWithStreamingHook(ctx, cmdArgs, username, groupname, env, timeout, pidHook, chunkCallback)
	if cleanup != nil {
		cleanup()
	}
	return exitCode, output
}
