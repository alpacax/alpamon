package executor

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"github.com/alpacax/alpamon/pkg/utils"
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
			return 1, err.Error(), err
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
	output, err := cmd.CombinedOutput()
	exitCode := 0
	if err != nil {
		if exitError, ok := err.(*exec.ExitError); ok {
			exitCode = exitError.ExitCode()
		} else {
			exitCode = 1
		}
	}

	return exitCode, string(output), err
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
		"PATH":      "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"HOME":      os.Getenv("HOME"),
		"USER":      os.Getenv("USER"),
		"SHELL":     "/bin/bash",
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
