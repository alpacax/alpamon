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
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/alpacax/alpamon/v2/pkg/config"
	"github.com/rs/zerolog/log"
	"github.com/shirou/gopsutil/v4/mem"
)

// CodeServerConfig holds all code-server configuration in one place.
type CodeServerConfig struct {
	// Timeouts
	InstallTimeout time.Duration
	StartupTimeout time.Duration
	IdleTimeout    time.Duration

	// Paths
	UserDataDirName  string
	InstallScriptURL string

	// Daemon settings (config.yaml)
	Auth               string
	DisableTelemetry   bool
	DisableUpdateCheck bool

	// Editor settings (settings.json)
	ColorTheme                string
	WindowTitle               string
	TelemetryLevel            string
	StartupEditor             string
	RestoreWindows            string
	UpdateMode                string
	DisableWorkspaceTrust     bool
	DisableWelcomeWalkthrough bool

	// Extension gallery
	ExtensionGalleryServiceURL string
	ExtensionGalleryItemURL    string
}

// Minimum free memory required to start code-server.
const minFreeMemoryForEditor uint64 = 512 * 1024 * 1024 // 512MB

var codeServerStopGrace = 10 * time.Second

// defaultConfig is the singleton configuration instance.
var defaultConfig = &CodeServerConfig{
	// Timeouts
	InstallTimeout: 5 * time.Minute,
	StartupTimeout: 30 * time.Second,
	IdleTimeout:    1 * time.Hour,

	// Paths
	UserDataDirName:  ".alpamon-editor",
	InstallScriptURL: "https://code-server.dev/install.sh",

	// Daemon settings
	Auth:               "none",
	DisableTelemetry:   true,
	DisableUpdateCheck: true,

	// Editor settings
	ColorTheme:                "Default Dark Modern",
	WindowTitle:               "${dirty}${activeEditorShort}${separator}${rootName}${separator}Alpamon Editor",
	TelemetryLevel:            "off",
	StartupEditor:             "none",
	RestoreWindows:            "none",
	UpdateMode:                "none",
	DisableWorkspaceTrust:     true,
	DisableWelcomeWalkthrough: true,

	// Extension gallery (OpenVSX)
	ExtensionGalleryServiceURL: "https://open-vsx.org/vscode/gallery",
	ExtensionGalleryItemURL:    "https://open-vsx.org/vscode/item",
}

var configOnce sync.Once

// GetCodeServerConfig returns the code-server configuration.
// On the first call, it applies the editor idle timeout from alpamon.conf.
func GetCodeServerConfig() *CodeServerConfig {
	configOnce.Do(func() {
		defaultConfig.IdleTimeout = time.Duration(config.GlobalSettings.EditorIdleTimeout) * time.Minute
	})
	return defaultConfig
}

// checkEditorResources verifies sufficient memory is available for code-server.
// Uses fail-open policy: if metrics cannot be retrieved, startup is allowed.
func checkEditorResources() error {
	memInfo, err := mem.VirtualMemory()
	if err != nil {
		return nil
	}
	if memInfo.Available < minFreeMemoryForEditor {
		return fmt.Errorf("insufficient memory: %dMB available, %dMB required",
			memInfo.Available/1024/1024, minFreeMemoryForEditor/1024/1024)
	}
	return nil
}

// ToConfigYAML generates config.yaml content for code-server daemon.
func (c *CodeServerConfig) ToConfigYAML() string {
	return fmt.Sprintf("auth: %s\ndisable-telemetry: %t\ndisable-update-check: %t\n",
		c.Auth, c.DisableTelemetry, c.DisableUpdateCheck)
}

// codeServerSettings is the settings.json body for the code-server editor.
// Fields follow CodeServerConfig's editor-settings order; the emitted key
// order is JSON-irrelevant and locked by TestToSettingsJSONGolden.
type codeServerSettings struct {
	ColorTheme            string `json:"workbench.colorTheme"`
	WindowTitle           string `json:"window.title"`
	TelemetryLevel        string `json:"telemetry.telemetryLevel"`
	StartupEditor         string `json:"workbench.startupEditor"`
	RestoreWindows        string `json:"window.restoreWindows"`
	UpdateMode            string `json:"update.mode"`
	WorkspaceTrustEnabled bool   `json:"security.workspace.trust.enabled"`
	OpenWalkthrough       bool   `json:"workbench.welcomePage.walkthroughs.openOnInstall"`
}

// ToSettingsJSON generates settings.json content for VS Code editor.
func (c *CodeServerConfig) ToSettingsJSON() ([]byte, error) {
	settings := codeServerSettings{
		ColorTheme:            c.ColorTheme,
		WindowTitle:           c.WindowTitle,
		TelemetryLevel:        c.TelemetryLevel,
		StartupEditor:         c.StartupEditor,
		RestoreWindows:        c.RestoreWindows,
		UpdateMode:            c.UpdateMode,
		WorkspaceTrustEnabled: !c.DisableWorkspaceTrust,
		OpenWalkthrough:       !c.DisableWelcomeWalkthrough,
	}
	return json.MarshalIndent(settings, "", "  ")
}

// ToExtensionGalleryEnv generates the EXTENSIONS_GALLERY environment variable value.
func (c *CodeServerConfig) ToExtensionGalleryEnv() string {
	return fmt.Sprintf(`{"serviceUrl": "%s", "itemUrl": "%s"}`,
		c.ExtensionGalleryServiceURL, c.ExtensionGalleryItemURL)
}

// ToArgs generates command line arguments for code-server.
func (c *CodeServerConfig) ToArgs(port int, userDataDir string) []string {
	return []string{
		"--config", filepath.Join(userDataDir, "config.yaml"),
		"--user-data-dir", userDataDir,
		"--bind-addr", net.JoinHostPort(loopbackHost, strconv.Itoa(port)),
		"--idle-timeout-seconds", fmt.Sprintf("%d", int(c.IdleTimeout.Seconds())),
	}
}

// ToEnv generates environment variables for code-server process.
func (c *CodeServerConfig) ToEnv(homeDir string, includeXDG bool) []string {
	env := append(os.Environ(),
		fmt.Sprintf("HOME=%s", homeDir),
		fmt.Sprintf("EXTENSIONS_GALLERY=%s", c.ToExtensionGalleryEnv()),
	)

	if includeXDG {
		env = append(env,
			fmt.Sprintf("XDG_DATA_HOME=%s", filepath.Join(homeDir, ".local", "share")),
			fmt.Sprintf("XDG_CONFIG_HOME=%s", filepath.Join(homeDir, ".config")),
		)
	}

	return env
}

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
	waitDone  chan struct{}
	port      int
	username  string
	groupname string
	homeDir   string
	ctx       context.Context
	cancel    context.CancelFunc
	mu        sync.RWMutex
	started   bool
	status    CodeServerStatus
	lastError string
	startOnce sync.Once
	startErr  error
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

	if groupname != "" {
		if _, err := user.LookupGroup(groupname); err != nil {
			return nil, fmt.Errorf("group %s not found: %w", groupname, err)
		}
	}

	return usr, nil
}

// Status returns the current status and last error message.
func (m *CodeServerManager) Status() (CodeServerStatus, string) {
	m.mu.RLock()
	defer m.mu.RUnlock()
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
// Lock is held only for short field updates to avoid blocking Status()/Stop() during
// long-running install/startup operations.
func (m *CodeServerManager) Start() error {
	m.startOnce.Do(func() {
		m.startErr = m.doStart()
	})
	return m.startErr
}

// doStart performs the actual code-server installation and startup.
func (m *CodeServerManager) doStart() error {
	if err := checkEditorResources(); err != nil {
		return err
	}

	// Check if code-server is installed (long operation — no lock held)
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

	m.mu.Lock()
	m.status = CodeServerStatusStarting
	m.mu.Unlock()

	// Setup user data directory with settings (no lock needed)
	userDataDir, err := setupUserDataDir(m.homeDir, m.username, m.groupname)
	if err != nil {
		return fmt.Errorf("failed to setup user data dir: %w", err)
	}

	// Find available port (no lock needed)
	port, err := findAvailablePort()
	if err != nil {
		return fmt.Errorf("failed to find available port: %w", err)
	}

	// Set port before starting process (startCodeServerProcess reads m.port)
	m.mu.Lock()
	m.port = port
	m.mu.Unlock()

	// Start code-server process (no lock needed)
	cmd, err := startCodeServerProcess(m.ctx, m, userDataDir)
	if err != nil {
		return err
	}

	waitDone := reapProcess(cmd)

	m.mu.Lock()
	m.cmd = cmd
	m.waitDone = waitDone
	m.mu.Unlock()

	// Wait for code-server to be ready (no lock needed)
	if err := m.waitForReady(waitDone); err != nil {
		_ = m.Stop()
		return fmt.Errorf("code-server failed to start: %w", err)
	}

	m.mu.Lock()
	m.started = true
	m.status = CodeServerStatusReady
	m.mu.Unlock()

	log.Info().Msgf("code-server started successfully on port %d for user %s.", port, m.username)

	return nil
}

// A seam: a test needs signalling to fail without picking a pid it does not own.
var terminateProcessFn = terminateProcess

// reapProcess runs the only cmd.Wait this process gets—a second one would race it
// over cmd.ProcessState—and closes done, so every waiter sees the reap, not just one.
func reapProcess(cmd *exec.Cmd) chan struct{} {
	done := make(chan struct{})
	go func() {
		_ = cmd.Wait()
		close(done)
	}()
	return done
}

// Stop terminates code-server and waits for the reap, even before m.started is
// set—the doStart failure path. It takes m.mu itself, so a caller holding it
// deadlocks; the wait runs unlocked so Status() still answers.
func (m *CodeServerManager) Stop() error {
	m.mu.Lock()
	cmd, waitDone, port := m.cmd, m.waitDone, m.port
	m.cmd = nil
	m.waitDone = nil
	m.started = false
	m.mu.Unlock()

	if m.cancel != nil {
		defer m.cancel()
	}

	if cmd == nil || cmd.Process == nil {
		return nil
	}

	// A reaped pid is free for reuse: once the reaper is done, nothing here is ours.
	select {
	case <-waitDone:
		return nil
	default:
	}

	log.Info().Msgf("Stopping code-server on port %d...", port)

	// A failed signal still leaves a child to collect, so the wait below runs anyway.
	if err := terminateProcessFn(cmd.Process); err != nil {
		log.Warn().Err(err).Msg("Failed to signal code-server, waiting for it anyway.")
	}

	select {
	case <-waitDone:
		log.Info().Msg("code-server stopped.")
	case <-time.After(codeServerStopGrace):
		// Not terminateProcessFn: it would repeat the SIGTERM just ignored.
		if err := killProcess(cmd.Process); err != nil {
			log.Warn().Err(err).Msg("Failed to kill code-server after timeout.")
		}
		log.Warn().Msg("code-server killed after timeout.")
		return fmt.Errorf("code-server did not exit within %v", codeServerStopGrace)
	}

	return nil
}

// Port returns the port code-server is running on.
func (m *CodeServerManager) Port() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.port
}

// IsRunning checks if code-server is currently running.
func (m *CodeServerManager) IsRunning() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.started
}

// waitForReady waits for code-server to listen on its port. It watches the reaper
// channel, not m.cmd, which a concurrent Stop may have already cleared.
func (m *CodeServerManager) waitForReady(waitDone <-chan struct{}) error {
	cfg := GetCodeServerConfig()
	addr := net.JoinHostPort(loopbackHost, strconv.Itoa(m.port))
	deadline := time.After(cfg.StartupTimeout)

	for {
		conn, err := net.DialTimeout("tcp", addr, time.Second)
		if err == nil {
			_ = conn.Close()
			return nil
		}

		select {
		case <-waitDone:
			return fmt.Errorf("code-server process exited unexpectedly")
		case <-deadline:
			return fmt.Errorf("code-server not ready after %v", cfg.StartupTimeout)
		case <-time.After(time.Second):
		}
	}
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
	cfg := GetCodeServerConfig()
	ctx, cancel := context.WithTimeout(parentCtx, cfg.InstallTimeout)
	defer cancel()

	script, err := downloadInstallScript(cfg.InstallScriptURL)
	if err != nil {
		return err
	}

	cmd := exec.CommandContext(ctx, "sh")
	cmd.Stdin = bytes.NewReader(script)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	// HOME is required by install script but not set in systemd service
	homeDir := "/root"
	if runtime.GOOS == "darwin" {
		usr, err := user.Current()
		if err != nil {
			log.Error().Err(err).Msg("failed to determine current user on macOS")
			return fmt.Errorf("failed to determine current user on macOS: %w", err)
		}
		homeDir = usr.HomeDir
	}

	env := os.Environ()
	cmd.Env = make([]string, 0, len(env)+1)
	for _, e := range env {
		if !strings.HasPrefix(e, "HOME=") {
			cmd.Env = append(cmd.Env, e)
		}
	}
	cmd.Env = append(cmd.Env, fmt.Sprintf("HOME=%s", homeDir))

	if err := cmd.Run(); err != nil {
		log.Error().Err(err).Msg("code-server install script failed.")
		return fmt.Errorf("install script failed: %w", err)
	}

	return nil
}

func downloadInstallScript(url string) ([]byte, error) {
	client := &http.Client{
		Timeout: 30 * time.Second,
	}
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to download install script: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

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
	listener, err := net.Listen("tcp", net.JoinHostPort(loopbackHost, "0"))
	if err != nil {
		return 0, fmt.Errorf("failed to find available port: %w", err)
	}
	defer func() { _ = listener.Close() }()
	return listener.Addr().(*net.TCPAddr).Port, nil
}

// getCodeServerArgs returns the command line arguments for code-server.
func getCodeServerArgs(port int, userDataDir string) []string {
	return GetCodeServerConfig().ToArgs(port, userDataDir)
}

// getCodeServerEnv returns environment variables for code-server process.
func getCodeServerEnv(homeDir string, includeXDG bool) []string {
	return GetCodeServerConfig().ToEnv(homeDir, includeXDG)
}

// setupUserDataDir creates the user-data-dir with config.yaml and settings.json for code-server.
// If running as root on Linux, ownership of created files is changed to the specified user.
func setupUserDataDir(homeDir, username, groupname string) (string, error) {
	cfg := GetCodeServerConfig()
	userDataDir := filepath.Join(homeDir, cfg.UserDataDirName)
	userDir := filepath.Join(userDataDir, "User")

	// Create directories
	if err := os.MkdirAll(userDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create user data dir: %w", err)
	}

	// Create config.yaml for code-server daemon settings
	configPath := filepath.Join(userDataDir, "config.yaml")
	if err := os.WriteFile(configPath, []byte(cfg.ToConfigYAML()), 0644); err != nil {
		return "", fmt.Errorf("failed to write config.yaml: %w", err)
	}

	// Create settings.json for VS Code editor settings
	settingsPath := filepath.Join(userDir, "settings.json")
	data, err := cfg.ToSettingsJSON()
	if err != nil {
		return "", fmt.Errorf("failed to marshal settings: %w", err)
	}

	if err := os.WriteFile(settingsPath, data, 0644); err != nil {
		return "", fmt.Errorf("failed to write settings.json: %w", err)
	}

	// Change ownership if running as root (so demoted user can modify their config)
	if os.Getuid() == 0 && runtime.GOOS != "darwin" {
		if err := chownUserDataDir(userDataDir, username, groupname); err != nil {
			log.Warn().Err(err).Msg("Failed to change ownership of user data dir.")
		}
	}

	log.Debug().Msgf("Created user data directory at %s with config.", userDataDir)
	return userDataDir, nil
}

// chownUserDataDir changes ownership of the user data directory and its contents.
func chownUserDataDir(userDataDir, username, groupname string) error {
	usr, err := user.Lookup(username)
	if err != nil {
		return fmt.Errorf("user %s not found: %w", username, err)
	}

	uid, err := strconv.Atoi(usr.Uid)
	if err != nil {
		return fmt.Errorf("invalid uid: %w", err)
	}

	// Use user's primary group if groupname is empty
	gidStr := usr.Gid
	if groupname != "" {
		group, err := user.LookupGroup(groupname)
		if err != nil {
			return fmt.Errorf("group %s not found: %w", groupname, err)
		}
		gidStr = group.Gid
	}

	gid, err := strconv.Atoi(gidStr)
	if err != nil {
		return fmt.Errorf("invalid gid: %w", err)
	}

	// Recursively change ownership
	return filepath.Walk(userDataDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		return os.Chown(path, uid, gid)
	})
}
