package executor

import (
	"bytes"
	"context"
	"fmt"
	"os"
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
	// Apply environment variable substitution
	args := e.substituteEnvVars(opts.Args, opts.Env)

	// Setup context with timeout if specified
	if opts.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, opts.Timeout)
		defer cancel()
	}

	// Create command
	// codeql[go/command-injection]: Intentional - Alpamon executes admin commands from Alpacon console
	cmd := exec.CommandContext(ctx, args[0], args[1:]...) // lgtm[go/command-injection]

	// Set up privilege demotion if username specified
	if opts.Username != "" && opts.Username != "root" {
		sysProcAttr, err := e.demotePrivileges(opts.Username, opts.Groupname)
		if err != nil {
			log.Error().Err(err).Msg("Failed to demote privileges")
			msg := err.Error()
			if opts.ChunkCallback != nil {
				// In-band so streaming UIs don't see an empty terminal then fin.
				safeInvokeChunkCallback(opts.ChunkCallback, "alpamon: "+msg+"\n")
				return 1, "", err
			}
			return 1, msg, err
		}
		if sysProcAttr != nil {
			cmd.SysProcAttr = sysProcAttr
		}
	}

	// Set environment variables
	for key, value := range opts.Env {
		cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%s", key, value))
	}

	// Set working directory
	if opts.WorkingDir != "" {
		cmd.Dir = opts.WorkingDir
	} else if opts.Username != "" {
		usr, err := utils.GetSystemUser(opts.Username)
		if err == nil {
			cmd.Dir = usr.HomeDir
		}
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
	output, err := e.runCommand(cmd, opts.PIDHook, opts.ChunkCallback)
	exitCode := 0
	result := string(output)
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			elapsed := time.Since(start).Truncate(time.Second)
			msg := fmt.Sprintf("Command timed out after %s", elapsed)
			if opts.ChunkCallback != nil {
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
func (e *Executor) runCommand(cmd *exec.Cmd, pidHook func(pid int), chunkCallback func(content string)) ([]byte, error) {
	if chunkCallback != nil {
		cw := newChunkWriter(chunkCallback)
		cmd.Stdout = cw
		cmd.Stderr = cw

		if err := cmd.Start(); err != nil {
			return nil, err
		}
		if cmd.Process != nil {
			invokePIDHook(pidHook, cmd.Process.Pid)
		}
		err := cmd.Wait()
		cw.Flush()
		return nil, err
	}

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
		invokePIDHook(pidHook, cmd.Process.Pid)
	}

	err := cmd.Wait()
	return buf.Bytes(), err
}

// safeInvokeChunkCallback is for pre-launch error paths that bypass the
// writer. Safe ONLY before cmd.Start — after Start, use chunkWriter.emit
// so w.mu serializes against concurrent stdout/stderr writes.
func safeInvokeChunkCallback(cb func(content string), content string) {
	if cb == nil {
		return
	}
	defer func() {
		if r := recover(); r != nil {
			log.Error().Interface("panic", r).Msg("ChunkCallback panicked")
		}
	}()
	cb(content)
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

// substituteEnvVars replaces environment variables in arguments
func (e *Executor) substituteEnvVars(args []string, env map[string]string) []string {
	if env == nil {
		return args
	}

	// Add default environment variables
	defaultEnv := e.getDefaultEnv()
	for key, value := range defaultEnv {
		if _, exists := env[key]; !exists {
			env[key] = value
		}
	}

	// Substitute variables in arguments
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

// getDefaultEnv returns default environment variables
func (e *Executor) getDefaultEnv() map[string]string {
	return map[string]string{
		"PATH":      utils.DefaultPath(),
		"HOME":      os.Getenv("HOME"),
		"USER":      os.Getenv("USER"),
		"SHELL":     utils.DefaultShell(),
		"TERM":      "xterm-256color",
		"LANG":      "en_US.UTF-8",
		"LS_COLORS": `rs=0:di=01;34:ln=01;36:mh=00:pi=40;33:so=01;35:do=01;35:bd=40;33;01:cd=40;33;01:or=40;31;01:mi=00:su=37;41:sg=30;43:ca=30;41:tw=30;42:ow=34;42:st=37;44:ex=01;32:*.tar=01;31:*.tgz=01;31:*.arc=01;31:*.arj=01;31:*.taz=01;31:*.lha=01;31:*.lz4=01;31:*.lzh=01;31:*.lzma=01;31:*.tlz=01;31:*.txz=01;31:*.tzo=01;31:*.t7z=01;31:*.zip=01;31:*.z=01;31:*.Z=01;31:*.dz=01;31:*.gz=01;31:*.lrz=01;31:*.lz=01;31:*.lzo=01;31:*.xz=01;31:*.bz2=01;31:*.bz=01;31:*.tbz=01;31:*.tbz2=01;31:*.tz=01;31:*.deb=01;31:*.rpm=01;31:*.jar=01;31:*.war=01;31:*.ear=01;31:*.sar=01;31:*.rar=01;31:*.alz=01;31:*.ace=01;31:*.zoo=01;31:*.cpio=01;31:*.7z=01;31:*.rz=01;31:*.cab=01;31:*.jpg=01;35:*.jpeg=01;35:*.gif=01;35:*.bmp=01;35:*.pbm=01;35:*.pgm=01;35:*.ppm=01;35:*.tga=01;35:*.xbm=01;35:*.xpm=01;35:*.tif=01;35:*.tiff=01;35:*.png=01;35:*.svg=01;35:*.svgz=01;35:*.mng=01;35:*.pcx=01;35:*.mov=01;35:*.mpg=01;35:*.mpeg=01;35:*.m2v=01;35:*.mkv=01;35:*.webm=01;35:*.ogm=01;35:*.mp4=01;35:*.m4v=01;35:*.mp4v=01;35:*.vob=01;35:*.qt=01;35:*.nuv=01;35:*.wmv=01;35:*.asf=01;35:*.rm=01;35:*.rmvb=01;35:*.flc=01;35:*.avi=01;35:*.fli=01;35:*.flv=01;35:*.gl=01;35:*.dl=01;35:*.xcf=01;35:*.xwd=01;35:*.yuv=01;35:*.cgm=01;35:*.emf=01;35:*.ogv=01;35:*.ogx=01;35:*.aac=00;36:*.au=00;36:*.flac=00;36:*.m4a=00;36:*.mid=00;36:*.midi=00;36:*.mka=00;36:*.mp3=00;36:*.mpc=00;36:*.ogg=00;36:*.ra=00;36:*.wav=00;36:*.oga=00;36:*.opus=00;36:*.spx=00;36:*.xspf=00;36:`,
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
