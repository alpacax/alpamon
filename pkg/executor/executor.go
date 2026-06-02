package executor

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/alpacax/alpamon/v2/pkg/utils"
	"github.com/rs/zerolog/log"
)

const chunkSizeThreshold = 4 * 1024

// chunkWriter forwards stdout/stderr to a callback on newline or at
// chunkSizeThreshold. No capture: chunks are the only output channel.
type chunkWriter struct {
	mu       sync.Mutex
	buf      bytes.Buffer
	callback func(content string)
}

func newChunkWriter(callback func(content string)) *chunkWriter {
	return &chunkWriter{callback: callback}
}

func (w *chunkWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	w.buf.Write(p)

	for {
		line, err := w.buf.ReadString('\n')
		if err == nil {
			// A buffered tail merged with this Write can exceed the cap.
			w.emitChunked(line)
			continue
		}
		for len(line) >= chunkSizeThreshold {
			w.emit(line[:chunkSizeThreshold])
			line = line[chunkSizeThreshold:]
		}
		if len(line) > 0 {
			w.buf.WriteString(line)
		}
		break
	}

	return len(p), nil
}

func (w *chunkWriter) Flush() {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.buf.Len() > 0 {
		content := w.buf.String()
		w.buf.Reset()
		w.emitChunked(content)
	}
}

func (w *chunkWriter) emitChunked(content string) {
	for len(content) > chunkSizeThreshold {
		w.emit(content[:chunkSizeThreshold])
		content = content[chunkSizeThreshold:]
	}
	if len(content) > 0 {
		w.emit(content)
	}
}

// emit nil-guards and recovers from callback panics so a bad callback
// cannot crash the agent.
func (w *chunkWriter) emit(content string) {
	if w.callback == nil {
		return
	}
	// Clone so a chunk sliced from a larger line or buffer doesn't pin the
	// full backing array alive while the chunk is queued downstream.
	content = strings.Clone(content)
	defer func() {
		if r := recover(); r != nil {
			log.Error().Interface("panic", r).Msg("ChunkCallback panicked")
		}
	}()
	w.callback(content)
}

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

	var cw *chunkWriter
	if opts.ChunkCallback != nil {
		cw = newChunkWriter(opts.ChunkCallback)
	}

	// Set up privilege demotion if username specified
	if opts.Username != "" && opts.Username != "root" {
		sysProcAttr, err := e.demotePrivileges(opts.Username, opts.Groupname)
		if err != nil {
			log.Error().Err(err).Msg("Failed to demote privileges")
			msg := err.Error()
			if cw != nil {
				// In-band so streaming UIs don't see an empty terminal then fin.
				cw.emit("alpamon: " + msg + "\n")
			}
			// Return msg in result so the fin payload still carries the
			// diagnostic if chunk delivery fails, consistent with the
			// streaming timeout path.
			return 1, msg, err
		}
		if sysProcAttr != nil {
			cmd.SysProcAttr = sysProcAttr
		}
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
	output, err := e.runCommand(cmd, opts.PIDHook, cw)
	exitCode := 0
	result := string(output)
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			elapsed := time.Since(start).Truncate(time.Second)
			msg := fmt.Sprintf("Command timed out after %s", elapsed)
			if cw != nil {
				return 124, msg, err
			}
			return 124, result + "\n\n" + msg, err
		}
		if exitError, ok := err.(*exec.ExitError); ok {
			exitCode = exitError.ExitCode()
		} else {
			// cmd.Start failures (ENOENT, fork EAGAIN) produce no bytes;
			// surface err so fin carries a diagnostic.
			exitCode = 1
			if result == "" {
				result = err.Error()
			}
		}
	}

	return exitCode, result, err
}

// runCommand uses Start/Wait when streaming or pid reporting is needed;
// otherwise CombinedOutput. The streaming path returns no bytes.
func (e *Executor) runCommand(cmd *exec.Cmd, pidHook func(pid int), cw *chunkWriter) ([]byte, error) {
	if cw == nil && pidHook == nil {
		return cmd.CombinedOutput()
	}

	var buf bytes.Buffer
	if cw != nil {
		cmd.Stdout = cw
		cmd.Stderr = cw
	} else {
		cmd.Stdout = &buf
		cmd.Stderr = &buf
	}

	if err := cmd.Start(); err != nil {
		if cw != nil {
			return nil, err
		}
		return buf.Bytes(), err
	}
	if cmd.Process != nil {
		invokePIDHook(pidHook, cmd.Process.Pid)
	}
	err := cmd.Wait()
	if cw != nil {
		cw.Flush()
		return nil, err
	}
	return buf.Bytes(), err
}

func invokePIDHook(pidHook func(pid int), pid int) {
	if pidHook == nil {
		return
	}
	defer func() {
		if r := recover(); r != nil {
			log.Error().Interface("panic", r).Int("pid", pid).Msg("PIDHook panicked")
		}
	}()
	pidHook(pid)
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

	// PIDHook, if non-nil, receives the child's pid after Start so the
	// shell handler can register it with the PAM tracker before the
	// child execs sudo. Panics are recovered and logged.
	PIDHook func(pid int)

	// ChunkCallback, if non-nil, receives streamed stdout/stderr chunks.
	// Sequencing is the caller's responsibility.
	ChunkCallback func(content string)
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

// ExecWithStreamingHook combines PIDHook and ChunkCallback. Either may be nil.
func (e *Executor) ExecWithStreamingHook(ctx context.Context, args []string, username, groupname string, env map[string]string, timeout time.Duration, pidHook func(pid int), chunkCallback func(content string)) (int, string, error) {
	return e.Execute(ctx, CommandOptions{
		Args:          args,
		Username:      username,
		Groupname:     groupname,
		Env:           env,
		Timeout:       timeout,
		PIDHook:       pidHook,
		ChunkCallback: chunkCallback,
	})
}
