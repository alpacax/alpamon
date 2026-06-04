package executor

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"github.com/alpacax/alpamon/v2/pkg/utils"
	"github.com/rs/zerolog/log"
)

// Executor provides system command execution with privilege management
type Executor struct{}

// NewExecutor creates a new system command executor
func NewExecutor() *Executor {
	return &Executor{}
}

// Execute runs a command with full control over execution parameters
func (e *Executor) Execute(ctx context.Context, opts CommandOptions) (int, string, error) {
	// Build the environment for the (possibly demoted) command and expand
	// any variable references in the arguments using it.
	env := e.buildEnv(opts.Username, opts.Env)
	args := e.expandArgs(opts.Args, env)

	// Setup context with timeout if specified
	if opts.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, opts.Timeout)
		defer cancel()
	}

	// Create command
	// codeql[go/command-injection]: Intentional - Alpamon executes admin commands from Alpacon console
	cmd := exec.CommandContext(ctx, args[0], args[1:]...) // lgtm[go/command-injection]

	// exec.CommandContext resolves a bare executable name against Alpamon's
	// process PATH, not the env built for the child below. Re-resolve it against
	// the child's PATH so command lookup and execution share one environment. On
	// Unix, a bare command missing from the child PATH is treated as not found
	// rather than falling back to the service PATH; Windows keeps the standard
	// resolution.
	utils.ApplyCommandPath(cmd, args[0], env["PATH"])

	// Set up privilege demotion if username specified
	if opts.Username != "" && opts.Username != "root" {
		sysProcAttr, err := e.demotePrivileges(opts.Username, opts.Groupname)
		if err != nil {
			log.Error().Err(err).Msg("Failed to demote privileges")
			return 1, err.Error(), err
		}
		if sysProcAttr != nil {
			cmd.SysProcAttr = sysProcAttr
		}
	}

	// When a PID hook is registered (command exec / deploy shell), start the
	// command in its own session so sudo invoked inside it resolves back to this
	// Command by session ID—even if the shell execs sudo and they share a pid
	// (see auth_manager session resolution). Gated on the hook to keep the blast
	// radius to the sudo-tracked path.
	if opts.PIDHook != nil {
		enableSessionLeader(cmd)
	}

	// Set the environment explicitly so the child never inherits Alpamon's
	// own service environment (e.g. USER=root, systemd-injected variables).
	for key, value := range env {
		cmd.Env = append(cmd.Env, key+"="+value)
	}

	// Set working directory. Reuse the home directory already resolved into
	// the environment instead of looking the user up a second time.
	if opts.WorkingDir != "" {
		cmd.Dir = opts.WorkingDir
	} else if opts.Username != "" {
		cmd.Dir = env["HOME"]
	}

	// Set stdin if provided
	if opts.Input != "" {
		cmd.Stdin = bytes.NewReader([]byte(opts.Input))
	}

	log.Debug().
		Str("command", strings.Join(args, " ")).
		Str("user", opts.Username).
		Str("group", opts.Groupname).
		Str("dir", cmd.Dir).
		Msg("Executor execute command")

	// Execute command
	start := time.Now()
	output, err := e.runCommand(cmd, opts.PIDHook)
	exitCode := 0
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			elapsed := time.Since(start).Truncate(time.Second)
			return 124, string(output) + fmt.Sprintf("\n\nCommand timed out after %s", elapsed), err
		}
		if exitError, ok := err.(*exec.ExitError); ok {
			exitCode = exitError.ExitCode()
		} else {
			exitCode = 1
		}
	}

	return exitCode, string(output), err
}

// runCommand executes cmd and returns its combined stdout/stderr output.
// When pidHook is non-nil, the command is started with cmd.Start() so the
// child's pid can be reported before Wait blocks. When pidHook is nil,
// the simpler cmd.CombinedOutput() path is used unchanged.
func (e *Executor) runCommand(cmd *exec.Cmd, pidHook func(pid int)) ([]byte, error) {
	if pidHook == nil {
		return cmd.CombinedOutput()
	}

	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf

	if err := cmd.Start(); err != nil {
		return buf.Bytes(), err
	}

	if cmd.Process != nil {
		pidHook(cmd.Process.Pid)
	}

	err := cmd.Wait()
	return buf.Bytes(), err
}

// CommandOptions defines options for command execution
type CommandOptions struct {
	Args       []string          // Command and arguments
	Username   string            // Username to run as (empty = current user)
	Groupname  string            // Group to run as
	Env        map[string]string // Environment variables
	WorkingDir string            // Working directory
	Timeout    time.Duration     // Command timeout
	Input      string            // Input to provide via stdin

	// PIDHook, if non-nil, is invoked with the child's pid immediately
	// after cmd.Start() returns successfully and before the command is
	// waited on. It is used to register the root pid of a deploy shell
	// Command with the PAM tracker so that sudo invoked inside the
	// command can be attributed to the originating Command.ID.
	//
	// When PIDHook is set, Execute uses cmd.Start()/cmd.Wait() instead
	// of cmd.CombinedOutput() so the pid is visible to the hook before
	// the child can exec sudo. Any panic from the hook is recovered and
	// logged without affecting command execution.
	PIDHook func(pid int)
}

// buildEnv constructs the environment for a command. It starts from the
// platform base environment (empty on Unix, the inherited process environment
// on Windows), layers the deterministic defaults and /etc/environment, fills in
// the target user's identity (HOME, USER, LOGNAME, MAIL) from the passwd entry,
// and finally applies any caller-provided variables as overrides. On Unix the
// child never inherits Alpamon's own service environment; on Windows the
// process environment is preserved so PowerShell keeps its required variables.
func (e *Executor) buildEnv(username string, override map[string]string) map[string]string {
	env := processBaseEnv()
	for key, value := range e.getDefaultEnv() {
		putEnv(env, key, value)
	}
	utils.LoadEtcEnvironment(env)
	e.applyUserIdentity(env, username)
	for key, value := range override {
		putEnv(env, key, value)
	}
	return env
}

// applyUserIdentity sets the identity-related environment variables from the
// target user's passwd entry, mirroring the Websh PTY path in
// getPtyUserAndEnv. When the user cannot be resolved, identity vars are left
// unset rather than falling back to Alpamon's process environment — that would
// leak the service identity (e.g. USER=root) into the demoted child and defeat
// the purpose of building the environment explicitly.
func (e *Executor) applyUserIdentity(env map[string]string, username string) {
	usr, err := utils.GetSystemUser(username)
	if err != nil {
		log.Warn().Err(err).Str("user", username).
			Msg("Failed to resolve user for environment; identity variables will be unset")
		if username != "" {
			putEnv(env, "USER", username)
			putEnv(env, "LOGNAME", username)
		}
		return
	}

	putEnv(env, "USER", usr.Username)
	putEnv(env, "HOME", usr.HomeDir)
	putEnv(env, "LOGNAME", usr.Username)
	putEnv(env, "MAIL", "/var/mail/"+usr.Username)
}

// expandArgs expands ${VAR} and $VAR references in each argument using env.
func (e *Executor) expandArgs(args []string, env map[string]string) []string {
	result := make([]string, len(args))
	for i, arg := range args {
		result[i] = e.expandEnvVar(arg, env)
	}
	return result
}

// expandEnvVar expands environment variables in a string
func (e *Executor) expandEnvVar(s string, env map[string]string) string {
	// Handle ${VAR} format
	if strings.HasPrefix(s, "${") && strings.HasSuffix(s, "}") {
		varName := s[2 : len(s)-1]
		if val, ok := env[varName]; ok {
			return val
		}
	}
	// Handle $VAR format
	if strings.HasPrefix(s, "$") {
		varName := s[1:]
		if val, ok := env[varName]; ok {
			return val
		}
	}
	return s
}

// getDefaultEnv returns the deterministic default environment variables.
// Identity variables (HOME, USER, LOGNAME, MAIL) are intentionally omitted
// here and set per target user in applyUserIdentity.
func (e *Executor) getDefaultEnv() map[string]string {
	return map[string]string{
		"PATH":      utils.DefaultPath(),
		"SHELL":     utils.DefaultShell(),
		"TERM":      "xterm-256color",
		"LANG":      "en_US.UTF-8",
		"LS_COLORS": utils.DefaultLSColors,
	}
}

// demotePrivileges creates syscall attributes for privilege demotion
func (e *Executor) demotePrivileges(username, groupname string) (*syscall.SysProcAttr, error) {
	result, err := utils.Demote(username, groupname, utils.DemoteOptions{ValidateGroup: true})
	if err != nil {
		return nil, err
	}
	if result == nil {
		return nil, nil
	}
	return result.SysProcAttr, nil
}

// Implement CommandExecutor interface methods

// Run executes a command with the given arguments
func (e *Executor) Run(ctx context.Context, name string, args ...string) (int, string, error) {
	allArgs := append([]string{name}, args...)
	return e.Execute(ctx, CommandOptions{Args: allArgs})
}

// RunAsUser executes a command as a specific user
func (e *Executor) RunAsUser(ctx context.Context, username string, name string, args ...string) (int, string, error) {
	allArgs := append([]string{name}, args...)
	return e.Execute(ctx, CommandOptions{
		Args:      allArgs,
		Username:  username,
		Groupname: username,
	})
}

// RunWithInput executes a command with stdin input
func (e *Executor) RunWithInput(ctx context.Context, input string, name string, args ...string) (int, string, error) {
	allArgs := append([]string{name}, args...)
	return e.Execute(ctx, CommandOptions{
		Args:  allArgs,
		Input: input,
	})
}

// RunWithTimeout executes a command with a timeout
func (e *Executor) RunWithTimeout(ctx context.Context, timeout time.Duration, name string, args ...string) (int, string, error) {
	allArgs := append([]string{name}, args...)
	return e.Execute(ctx, CommandOptions{
		Args:    allArgs,
		Timeout: timeout,
	})
}

// Exec executes a command with all options
func (e *Executor) Exec(ctx context.Context, args []string, username, groupname string, env map[string]string, timeout time.Duration) (int, string, error) {
	return e.Execute(ctx, CommandOptions{
		Args:      args,
		Username:  username,
		Groupname: groupname,
		Env:       env,
		Timeout:   timeout,
	})
}

// ExecWithHook is like Exec but registers a PIDHook that receives the
// child's pid immediately after cmd.Start() succeeds. This is used by
// the shell handler to track the root pid of a deploy shell Command so
// sudo calls made inside the command can be authorized via command_id.
func (e *Executor) ExecWithHook(ctx context.Context, args []string, username, groupname string, env map[string]string, timeout time.Duration, pidHook func(pid int)) (int, string, error) {
	return e.Execute(ctx, CommandOptions{
		Args:      args,
		Username:  username,
		Groupname: groupname,
		Env:       env,
		Timeout:   timeout,
		PIDHook:   pidHook,
	})
}
