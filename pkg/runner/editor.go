package runner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"sync"
	"syscall"
	"time"

	"github.com/rs/zerolog/log"
)

const (
	// Timeout configuration for code-server lifecycle
	installTimeout = 5 * time.Minute
	startupTimeout = 30 * time.Second
	idleTimeout    = 5 * time.Hour

	installScriptURL = "https://code-server.dev/install.sh"

	// Settings for code-server
	userDataDirName   = ".alpamon-editor"
	defaultColorTheme = "Default Dark Modern"
	codeServerConfig  = `auth: none
disable-telemetry: true
disable-update-check: true
`
)

// Common installation paths for code-server
var codeServerPaths = []string{
	"/usr/bin/code-server",
	"/usr/local/bin/code-server",
	"/opt/homebrew/bin/code-server", // macOS Homebrew
}

// CodeServerStatus represents the current state of code-server.
type CodeServerStatus string

const (
	CodeServerStatusIdle       CodeServerStatus = "idle"
	CodeServerStatusInstalling CodeServerStatus = "installing"
	CodeServerStatusStarting   CodeServerStatus = "starting"
	CodeServerStatusReady      CodeServerStatus = "ready"
	CodeServerStatusError      CodeServerStatus = "error"
)

// CodeServerManager manages a code-server process for editor tunneling.
type CodeServerManager struct {
	cmd       *exec.Cmd
	port      int
	username  string
	groupname string
	homeDir   string
	ctx       context.Context
	cancel    context.CancelFunc
	mu        sync.Mutex
	started   bool
	status    CodeServerStatus
	lastError string
}

func NewCodeServerManager(parentCtx context.Context, username, groupname string) (*CodeServerManager, error) {
	usr, err := lookupUserForCodeServer(username, groupname)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(parentCtx)

	return &CodeServerManager{
		username:  username,
		groupname: groupname,
		homeDir:   usr.HomeDir,
		ctx:       ctx,
		cancel:    cancel,
		status:    CodeServerStatusIdle,
	}, nil
}

func lookupUserForCodeServer(username, groupname string) (*user.User, error) {
	if runtime.GOOS == "darwin" {
		log.Debug().Msg("macOS: skipping credential demotion")
		return user.Current()
	}

	usr, err := user.Lookup(username)
	if err != nil {
		return nil, fmt.Errorf("user %s not found: %w", username, err)
	}

	if _, err := user.LookupGroup(groupname); err != nil {
		return nil, fmt.Errorf("group %s not found: %w", groupname, err)
	}

	return usr, nil
}

// Status returns the current status and last error message.
func (m *CodeServerManager) Status() (CodeServerStatus, string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.status, m.lastError
}

// StartAsync starts code-server installation/startup in background.
// Returns immediately. Use Status() to check progress.
func (m *CodeServerManager) StartAsync() {
	m.mu.Lock()
	if m.status != CodeServerStatusIdle {
		m.mu.Unlock()
		return
	}

	// Set initial status based on installation state
	if isCodeServerInstalled() {
		m.status = CodeServerStatusStarting
	} else {
		m.status = CodeServerStatusInstalling
	}
	m.mu.Unlock()

	go func() {
		if err := m.Start(); err != nil {
			m.mu.Lock()
			m.status = CodeServerStatusError
			m.lastError = err.Error()
			m.mu.Unlock()
			log.Error().Err(err).Msg("code-server startup failed.")
		}
	}()
}

// Start installs (if needed) and starts code-server on an available port.
func (m *CodeServerManager) Start() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.started {
		return nil
	}

	// Check if code-server is installed
	if !isCodeServerInstalled() {
		log.Info().Msg("code-server not found, installing...")
		if err := installCodeServer(m.ctx); err != nil {
			return fmt.Errorf("code-server installation failed: %w", err)
		}

		if !isCodeServerInstalled() {
			return fmt.Errorf("code-server installation completed but binary not found")
		}
		log.Info().Msg("code-server installed successfully.")
	}

	// Setup user data directory with settings
	userDataDir, err := setupUserDataDir(m.homeDir)
	if err != nil {
		return fmt.Errorf("failed to setup user data dir: %w", err)
	}

	// Find available port
	port, err := findAvailablePort()
	if err != nil {
		return fmt.Errorf("failed to find available port: %w", err)
	}
	m.port = port

	// Start code-server process
	cmd, err := startCodeServerProcess(m.ctx, m, userDataDir)
	if err != nil {
		return err
	}
	m.cmd = cmd

	// Wait for code-server to be ready
	if err := m.waitForReady(); err != nil {
		m.stopProcess()
		return fmt.Errorf("code-server failed to start: %w", err)
	}

	m.started = true
	m.status = CodeServerStatusReady
	log.Info().Msgf("code-server started successfully on port %d for user %s.", m.port, m.username)

	return nil
}

// Stop gracefully terminates the code-server process.
func (m *CodeServerManager) Stop() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	return m.stopProcess()
}

// stopProcess stops the code-server process
func (m *CodeServerManager) stopProcess() error {
	if !m.started || m.cmd == nil || m.cmd.Process == nil {
		return nil
	}

	log.Info().Msgf("Stopping code-server on port %d...", m.port)

	if m.cancel != nil {
		m.cancel()
	}

	if err := m.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		log.Debug().Err(err).Msg("SIGTERM failed, trying SIGKILL.")
		if err := m.cmd.Process.Kill(); err != nil {
			return fmt.Errorf("failed to kill code-server: %w", err)
		}
	}

	done := make(chan error, 1)
	go func() {
		done <- m.cmd.Wait()
	}()

	select {
	case <-done:
		log.Info().Msg("code-server stopped.")
	case <-time.After(10 * time.Second):
		_ = m.cmd.Process.Kill()
		log.Warn().Msg("code-server killed after timeout.")
	}

	m.started = false
	return nil
}

// Port returns the port code-server is running on.
func (m *CodeServerManager) Port() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.port
}

// IsRunning checks if code-server is currently running.
func (m *CodeServerManager) IsRunning() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.started
}

// waitForReady waits for code-server to start listening on its port.
func (m *CodeServerManager) waitForReady() error {
	addr := fmt.Sprintf("127.0.0.1:%d", m.port)
	deadline := time.Now().Add(startupTimeout)

	for time.Now().Before(deadline) {
		if m.cmd.ProcessState != nil && m.cmd.ProcessState.Exited() {
			return fmt.Errorf("code-server process exited unexpectedly")
		}

		conn, err := net.DialTimeout("tcp", addr, time.Second)
		if err == nil {
			conn.Close()
			return nil
		}

		time.Sleep(time.Second)
	}

	return fmt.Errorf("code-server not ready after %v", startupTimeout)
}

func isCodeServerInstalled() bool {
	_, err := getCodeServerPath()
	return err == nil
}

func getCodeServerPath() (string, error) {
	if path, err := exec.LookPath("code-server"); err == nil {
		return path, nil
	}

	for _, path := range codeServerPaths {
		if _, err := os.Stat(path); err == nil {
			return path, nil
		}
	}

	return "", fmt.Errorf("code-server not found")
}

// installCodeServer installs code-server using the official install script.
func installCodeServer(parentCtx context.Context) error {
	ctx, cancel := context.WithTimeout(parentCtx, installTimeout)
	defer cancel()

	script, err := downloadInstallScript()
	if err != nil {
		return err
	}

	cmd := exec.CommandContext(ctx, "sh")
	cmd.Stdin = bytes.NewReader(script)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("install script failed: %w", err)
	}

	return nil
}

func downloadInstallScript() ([]byte, error) {
	resp, err := http.Get(installScriptURL)
	if err != nil {
		return nil, fmt.Errorf("failed to download install script: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to download install script: HTTP %d", resp.StatusCode)
	}

	script, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read install script: %w", err)
	}

	return script, nil
}

// findAvailablePort finds an available port by letting the OS assign one.
func findAvailablePort() (int, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, fmt.Errorf("failed to find available port: %w", err)
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port, nil
}

// getCodeServerArgs returns the command line arguments for code-server.
func getCodeServerArgs(port int, userDataDir string) []string {
	return []string{
		"--config", filepath.Join(userDataDir, "config.yaml"),
		"--user-data-dir", userDataDir,
		"--bind-addr", fmt.Sprintf("127.0.0.1:%d", port),
		"--idle-timeout-seconds", fmt.Sprintf("%d", int(idleTimeout.Seconds())),
	}
}

// setupUserDataDir creates the user-data-dir with config.yaml and settings.json for code-server.
func setupUserDataDir(homeDir string) (string, error) {
	userDataDir := filepath.Join(homeDir, userDataDirName)
	userDir := filepath.Join(userDataDir, "User")

	// Create directories
	if err := os.MkdirAll(userDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create user data dir: %w", err)
	}

	// Create config.yaml for code-server daemon settings
	configPath := filepath.Join(userDataDir, "config.yaml")
	if err := os.WriteFile(configPath, []byte(codeServerConfig), 0644); err != nil {
		return "", fmt.Errorf("failed to write config.yaml: %w", err)
	}

	// Create settings.json for VS Code editor settings
	settings := map[string]interface{}{
		"workbench.colorTheme":                             defaultColorTheme,
		"workbench.startupEditor":                          "none",
		"workbench.welcomePage.walkthroughs.openOnInstall": false,
		"window.restoreWindows":                            "none",
		"telemetry.telemetryLevel":                         "off",
		"security.workspace.trust.enabled":                 false,
		"update.mode":                                      "none",
	}

	settingsPath := filepath.Join(userDir, "settings.json")
	data, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal settings: %w", err)
	}

	if err := os.WriteFile(settingsPath, data, 0644); err != nil {
		return "", fmt.Errorf("failed to write settings.json: %w", err)
	}

	log.Debug().Msgf("Created user data directory at %s with config.", userDataDir)
	return userDataDir, nil
}
