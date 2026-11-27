package runner

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/alpacax/alpamon/v2/internal/safego"
	"github.com/alpacax/alpamon/v2/pkg/config"
	"github.com/alpacax/alpamon/v2/pkg/utils"
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
	UserDataDirName string

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

const (
	codeServerReadyPollInterval = time.Second
	codeServerReadyDialTimeout  = time.Second
	codeServerStopGrace         = 10 * time.Second
)

// Layout of the user-data-dir that the platform-specific setupUserDataFiles
// writes; ToArgs points code-server at the config file.
const (
	userDataConfigFile   = "config.yaml"
	userDataUserDir      = "User"
	userDataSettingsFile = "settings.json"
)

// defaultConfig is the singleton configuration instance.
var defaultConfig = &CodeServerConfig{
	// Timeouts
	InstallTimeout: 5 * time.Minute,
	StartupTimeout: 30 * time.Second,
	IdleTimeout:    1 * time.Hour,

	// Paths
	UserDataDirName: ".alpamon-editor",

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
func (c *CodeServerConfig) ToArgs(socketPath string, userDataDir string) []string {
	return []string{
		"--config", filepath.Join(userDataDir, userDataConfigFile),
		"--user-data-dir", userDataDir,
		"--socket", socketPath,
		"--socket-mode", "600",
		"--idle-timeout-seconds", fmt.Sprintf("%d", int(c.IdleTimeout.Seconds())),
	}
}

// ToEnv generates environment variables for code-server process.
func (c *CodeServerConfig) ToEnv(homeDir string, includeXDG bool, username string) []string {
	env := utils.MinimalChildEnvironment(homeDir, username)
	if runtime.GOOS == "darwin" {
		for i, entry := range env {
			if strings.HasPrefix(entry, "PATH=") {
				env[i] += ":/opt/homebrew/bin:/opt/homebrew/sbin"
			}
		}
	}
	env = append(env, "EXTENSIONS_GALLERY="+c.ToExtensionGalleryEnv())
	for _, entry := range os.Environ() {
		key, value, _ := strings.Cut(entry, "=")
		switch key {
		case "HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy":
			if !strings.Contains(value, "://") {
				value = "http://" + value
			}
			proxy, err := url.Parse(value)
			if err != nil || proxy.Host == "" || proxy.Opaque != "" || proxy.RawQuery != "" || proxy.Fragment != "" || (proxy.Path != "" && proxy.Path != "/") {
				continue
			}
			env = append(env, key+"="+(&url.URL{Scheme: proxy.Scheme, Host: proxy.Host}).String())
		default:
			if editorPassthroughEnv(key) {
				env = append(env, entry)
			}
		}
	}

	if includeXDG {
		env = append(env,
			fmt.Sprintf("XDG_DATA_HOME=%s", filepath.Join(homeDir, ".local", "share")),
			fmt.Sprintf("XDG_CONFIG_HOME=%s", filepath.Join(homeDir, ".config")),
		)
	}

	return env
}

// rootCodeServerPrefix is where a root agent installs code-server, in a root-owned tree
// outside /usr/local, whose subdirs Homebrew hands to an admin account on Intel Macs.
const rootCodeServerPrefix = "/opt/alpamon/code-server"

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
	CodeServerStatusStopped    CodeServerStatus = "stopped" // final: Start runs once, and Stop cancels its context
)

// CodeServerManager manages a code-server process for editor tunneling.
type CodeServerManager struct {
	socketRemoved   bool
	socketRoot      *os.Root
	socketCleanupMu sync.Mutex
	peerWarnOnce    sync.Once
	proc            *codeServerProcess
	socketPath      string
	username        string
	groupname       string
	homeDir         string
	procAttr        *syscall.SysProcAttr // nil keeps Alpamon's own credentials
	ctx             context.Context
	cancel          context.CancelFunc
	mu              sync.RWMutex
	status          CodeServerStatus
	lastError       string
	startOnce       sync.Once
	startErr        error

	stopGrace        time.Duration
	terminateFn      func(*os.Process) error        // signals the process group while its leader remains unreaped
	prepareSocketDir func(*CodeServerManager) error // prepares an agent-owned base and editor-owned session directory
	dialReady        func() (net.Conn, error)       // probes readiness; nil dials the socket
}

// NewCodeServerManager runs the editor as the requested user for root agents.
// A non-root agent can start an editor only for its own account.
func NewCodeServerManager(parentCtx context.Context, username, groupname string) (*CodeServerManager, error) {
	id, err := lookupUserForCodeServer(username, groupname)
	if err != nil {
		return nil, err
	}

	if id.username != "" {
		username = id.username
	}
	ctx, cancel := context.WithCancel(parentCtx)

	return &CodeServerManager{
		username:   username,
		socketPath: filepath.Join(editorSocketBase(runtime.GOOS, os.Geteuid(), utils.RunDir()), rand.Text(), "cs.sock"),
		groupname:  id.groupname,
		homeDir:    id.homeDir,
		procAttr:   id.procAttr,
		ctx:        ctx,
		cancel:     cancel,
		status:     CodeServerStatusIdle,

		stopGrace:   codeServerStopGrace,
		terminateFn: terminateProcess,
	}, nil
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

	safego.Go("code-server async start", func() {
		if err := m.Start(); err != nil {
			m.mu.Lock()
			if m.setStatusLocked(CodeServerStatusError) {
				m.lastError = err.Error()
			}
			m.mu.Unlock()
			log.Error().Err(err).Msg("code-server startup failed.")
		}
	}, nil)
}

// Start installs (if needed) and starts code-server on its private socket.
// Lock is held only for short field updates to avoid blocking Status()/Stop() during
// long-running install/startup operations.
func (m *CodeServerManager) Start() error {
	m.startOnce.Do(func() {
		defer safego.Recover("code-server start", func() {
			m.startErr = errCodeServerPanicked // the Once is spent; without this, later Start calls report success
			_ = m.stopProcess()
			m.removeSocketDir() // stopProcess removes it only after a reap, and launch may have panicked before one
		})
		m.startErr = m.doStart()
	})
	return m.startErr
}

// doStart performs the actual code-server installation and startup.
func (m *CodeServerManager) doStart() error {
	if err := checkEditorResources(); err != nil {
		return err
	}

	// Install if missing (long operation—m.mu is not held)
	if err := ensureCodeServerInstalled(m.ctx); err != nil {
		return err
	}

	m.mu.Lock()
	starting := m.setStatusLocked(CodeServerStatusStarting)
	m.mu.Unlock()
	if !starting {
		return errCodeServerStopped
	}

	// Setup user data directory with settings (no lock needed)
	userDataDir, err := setupUserDataDir(m.ctx, m.homeDir, m.username, m.groupname)
	if err != nil {
		return fmt.Errorf("failed to setup user data dir: %w", err)
	}

	proc, err := m.launch(userDataDir)
	if err != nil {
		return err
	}
	safego.Go("code-server exit watcher", func() {
		<-proc.done
		m.mu.Lock()
		if m.status == CodeServerStatusReady {
			m.status = CodeServerStatusError
			m.lastError = "code-server exited"
		}
		m.mu.Unlock()
		m.removeSocketDir()
	}, nil)

	// Wait for code-server to be ready (no lock needed)
	if err := m.waitForReady(proc.done); err != nil {
		_ = m.stopProcess() // not Stop: the status has to carry this error
		return fmt.Errorf("code-server failed to start: %w", err)
	}

	m.mu.Lock()
	ready := m.setStatusLocked(CodeServerStatusReady)
	select {
	case <-proc.done:
		if ready {
			m.status = CodeServerStatusError
			m.lastError = "code-server exited"
		}
	default:
	}
	m.mu.Unlock()
	if !ready {
		return errCodeServerStopped // Stop took the process with it
	}

	log.Info().Msgf("code-server started successfully for user %s.", m.username)

	return nil
}

var (
	errCodeServerStopped  = errors.New("code-server was stopped while starting")
	errCodeServerPanicked = errors.New("code-server startup panicked")
)

// launch prepares the socket directory and starts code-server under m.mu, so
// Stop cannot slip in between; the deferred unlock keeps a panic from leaving m.mu held.
func (m *CodeServerManager) launch(userDataDir string) (*codeServerProcess, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.status == CodeServerStatusStopped || m.ctx.Err() != nil {
		return nil, errCodeServerStopped
	}
	prepare := m.prepareSocketDir
	if prepare == nil {
		prepare = prepareEditorSocketDir
	}
	if err := prepare(m); err != nil {
		return nil, fmt.Errorf("failed to prepare editor socket: %w", err)
	}
	cmd, err := startCodeServerProcess(m.ctx, m, userDataDir)
	if err != nil {
		m.removeSocketDir()
		return nil, err
	}
	m.proc = startReaper(cmd, waitExit)
	return m.proc, nil
}

// setStatusLocked moves m to status unless Stop got there first, so a start racing
// Stop cannot report a code-server that is gone. The caller holds m.mu.
func (m *CodeServerManager) setStatusLocked(status CodeServerStatus) bool {
	if m.status == CodeServerStatusStopped {
		return false
	}
	m.status = status
	return true
}

// codeServerProcess is a started code-server whose leader stays unreaped until its
// group has been killed.
type codeServerProcess struct {
	cmd       *exec.Cmd
	mu        sync.Mutex // held from a signal's check to its send, and over the kill and the reap
	done      chan struct{}
	unwatched bool // the exit could not be watched, so the reap runs unlocked
}

// startReaper owns the only cmd.Wait: a second one would race it over cmd.ProcessState.
// cmd must lead its own process group.
func startReaper(cmd *exec.Cmd, watchExit func(pid int) error) *codeServerProcess {
	p := &codeServerProcess{cmd: cmd, done: make(chan struct{})}
	// A reaper that panics falls back to the unswept wait, so done still closes once the leader exits.
	safego.Go("code-server reaper", func() { p.reap(watchExit) }, p.waitUnwatched)
	return p
}

func (p *codeServerProcess) reap(watchExit func(pid int) error) {
	if err := watchExit(p.cmd.Process.Pid); err != nil {
		// The leader may still be running, so the reap cannot hold p.mu against Stop.
		log.Debug().Err(err).Msg("Could not watch code-server exit, so its group is not swept.")
		p.waitUnwatched()
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	// Nothing else signals what the leader left behind.
	if err := killProcess(p.cmd.Process); err != nil && !errors.Is(err, syscall.ESRCH) {
		log.Debug().Err(err).Msg("Failed to kill what code-server left in its process group.")
	}
	p.wait()
}

// waitUnwatched reaps the leader without holding p.mu, so Stop can still kill it.
func (p *codeServerProcess) waitUnwatched() {
	p.mu.Lock()
	p.unwatched = true
	p.mu.Unlock()
	p.wait()
}

func (p *codeServerProcess) wait() {
	if err := p.cmd.Wait(); err != nil {
		log.Debug().Err(err).Msg("code-server process exited.")
	}
	close(p.done)
}

// signal calls fn on the leader unless it is reaped, which reports os.ErrProcessDone.
func (p *codeServerProcess) signal(fn func(*os.Process) error) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	select {
	case <-p.done:
		return os.ErrProcessDone
	default:
	}
	if p.unwatched {
		return p.cmd.Process.Kill() // the handle refuses once reaped, which a group signal cannot
	}
	return fn(p.cmd.Process)
}

// Stop terminates code-server and waits for the reap, even before it is
// ready—the doStart failure path. It takes m.mu itself, so a caller holding it
// deadlocks; the wait runs unlocked so Status() still answers.
func (m *CodeServerManager) Stop() error {
	m.mu.Lock()
	m.status = CodeServerStatusStopped
	m.mu.Unlock()
	return m.stopProcess()
}

// stopProcess is Stop without the final status, for doStart's failure path.
func (m *CodeServerManager) stopProcess() error {
	m.mu.Lock()
	proc := m.proc
	grace, terminate := m.stopGrace, m.terminateFn
	m.proc = nil
	m.mu.Unlock()

	if m.cancel != nil {
		defer m.cancel()
	}

	if proc == nil {
		return nil
	}
	defer func() {
		select {
		case <-proc.done:
			m.removeSocketDir()
		default:
		}
	}()

	// A reaped leader was the reaper's to sweep, so its pgid is nothing to signal.
	// A failed signal still leaves a child to collect, so the wait below runs anyway.
	switch err := proc.signal(terminate); {
	case errors.Is(err, os.ErrProcessDone):
		return nil
	case err != nil:
		log.Warn().Err(err).Msg("Failed to signal code-server, waiting for it anyway.")
	}
	log.Info().Msg("Stopping code-server...")

	timer := time.NewTimer(grace)
	defer timer.Stop()

	select {
	case <-proc.done:
	case <-timer.C:
		// Not terminate: it would repeat the SIGTERM just ignored.
		if killErr := proc.signal(killProcess); !errors.Is(killErr, os.ErrProcessDone) {
			log.Warn().Err(killErr).Dur("grace", grace).Msg("code-server did not exit in time, sending SIGKILL.")
			return fmt.Errorf("code-server did not exit within %v", grace)
		}
	}

	log.Info().Msg("code-server stopped.")
	return nil
}

// waitForReady waits for code-server to listen on its socket. It watches the reaper
// channel, not m.cmd, which a concurrent Stop may have already cleared.
func (m *CodeServerManager) waitForReady(waitDone <-chan struct{}) error {
	cfg := GetCodeServerConfig()
	deadline := time.NewTimer(cfg.StartupTimeout)
	defer deadline.Stop()

	ticker := time.NewTicker(codeServerReadyPollInterval)
	defer ticker.Stop()

	dial := m.dialSocket
	if m.dialReady != nil {
		dial = m.dialReady
	}
	for {
		// A completed process cannot be ready, even if its socket still answers.
		select {
		case <-waitDone:
			return fmt.Errorf("code-server process exited unexpectedly")
		default:
		}

		conn, err := dial()
		if err == nil {
			_ = conn.Close()
			return nil
		}

		select {
		case <-waitDone:
			// The loop head reports it.
		case <-deadline.C:
			return fmt.Errorf("code-server not ready after %v", cfg.StartupTimeout)
		case <-ticker.C:
		}
	}
}

// codeServerIdentity is who code-server runs as; a nil procAttr keeps Alpamon's own credentials.
type codeServerIdentity struct {
	username  string
	homeDir   string
	groupname string
	procAttr  *syscall.SysProcAttr
}

func lookupUserForCodeServer(username, groupname string) (*codeServerIdentity, error) {
	if os.Geteuid() != 0 {
		if runtime.GOOS != "darwin" && groupname == "" {
			return nil, fmt.Errorf("groupname is required")
		}
		usr, err := user.LookupId(strconv.Itoa(os.Geteuid()))
		if err != nil {
			return nil, err
		}
		requested, err := user.Lookup(username)
		if err != nil || requested.Uid != usr.Uid {
			return nil, fmt.Errorf("cannot start editor for %s: agent must run as the requested account or root", username)
		}
		return &codeServerIdentity{username: usr.Username, homeDir: usr.HomeDir, groupname: groupname}, nil
	}
	if runtime.GOOS == "darwin" {
		// The server sends a Linux group name, so macOS demotes to the user's primary group.
		var err error
		if groupname, err = primaryGroupName(username); err != nil {
			return nil, err
		}
	}
	result, err := utils.Demote(username, groupname, utils.DemoteOptions{ValidateGroup: true})
	if err != nil {
		return nil, err
	}
	if result != nil {
		return &codeServerIdentity{homeDir: result.User.HomeDir, groupname: groupname, procAttr: result.SysProcAttr}, nil
	}

	usr, err := user.Lookup(username)
	if err != nil {
		return nil, fmt.Errorf("user %s not found: %w", username, err)
	}

	return &codeServerIdentity{username: usr.Username, homeDir: usr.HomeDir, groupname: groupname}, nil
}

func primaryGroupName(username string) (string, error) {
	usr, err := user.Lookup(username)
	if err != nil {
		return "", fmt.Errorf("there is no corresponding %s username in this server: %w", username, err)
	}
	grp, err := user.LookupGroupId(usr.Gid)
	if err != nil {
		return "", fmt.Errorf("failed to lookup primary group of %s: %w", username, err)
	}
	return grp.Name, nil
}

func isCodeServerInstalled() bool {
	_, err := getCodeServerPath()
	return err == nil
}

func getCodeServerPath() (string, error) {
	return lookupCodeServerPath(runtime.GOOS, os.Getuid() == 0, editorInstallPrefix)
}

// lookupCodeServerPath limits a root macOS host to its own install, since a binary on PATH or under
// Homebrew may be one another account can change.
func lookupCodeServerPath(goos string, isRoot bool, installPrefix func() (string, error)) (string, error) {
	if prefix, err := installPrefix(); err == nil {
		release := filepath.Join(prefix, "v"+editorReleaseVersion)
		candidate := filepath.Join(release, "bin", "code-server")
		if _, err := os.Lstat(release); !errors.Is(err, os.ErrNotExist) {
			if isRoot {
				err = checkEditorRelease(release)
			} else {
				err = checkEditorRuntime(release)
			}
			if err == nil {
				return candidate, nil
			}
			if isRoot {
				return "", err
			}
		}
	}
	if goos == "darwin" && isRoot {
		path := filepath.Join(rootCodeServerPrefix, "bin", "code-server")
		if !isExecutableFile(path) {
			return "", fmt.Errorf("code-server not found")
		}
		return path, nil
	}

	if path, err := exec.LookPath("code-server"); err == nil {
		return path, nil
	}

	if !isRoot {
		if home, err := os.UserHomeDir(); err == nil && filepath.IsAbs(home) {
			path := filepath.Join(home, ".local", "bin", "code-server")
			if isExecutableFile(path) {
				return path, nil
			}
		}
	}

	for _, path := range codeServerPaths {
		if isExecutableFile(path) {
			return path, nil
		}
	}

	return "", fmt.Errorf("code-server not found")
}

func isExecutableFile(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular() && info.Mode().Perm()&0111 != 0
}

// codeServerInstallMu serializes installs across editor sessions, which share one install dir.
var codeServerInstallMu sync.Mutex

func ensureCodeServerInstalled(ctx context.Context) error {
	codeServerInstallMu.Lock()
	defer codeServerInstallMu.Unlock()

	if isCodeServerInstalled() {
		return nil
	}
	log.Info().Msg("code-server not found, installing...")
	if err := installCodeServer(ctx); err != nil {
		return fmt.Errorf("code-server installation failed: %w", err)
	}

	if !isCodeServerInstalled() {
		return fmt.Errorf("code-server installation completed but binary not found")
	}
	log.Info().Msg("code-server installed successfully.")
	return nil
}

const editorReleaseVersion = "4.146.0"
const editorReleaseMarker = ".alpamon-verified"

var tarBinaries = []string{"/usr/bin/tar", "/bin/tar"}

func findEditorTar(candidates []string) (string, error) {
	for _, path := range candidates {
		if info, err := os.Stat(path); err == nil && info.Mode().IsRegular() && info.Mode().Perm()&0111 != 0 {
			return path, nil
		}
	}
	return "", fmt.Errorf("code-server installation requires tar at one of %v", candidates)
}

var editorReleaseDigests = map[string]string{
	"linux-amd64": "cf7e82ca5fe1df664d43a43d900c3c9710f8f3403a5e8d0e18f6a12d10d7401b",
	"linux-arm64": "3df88f7f1feecce3583ab0109c5f6bf14f90ae3a44939b4257ccd9850ef37a6e",
	"macos-amd64": "57f4df733efc49651c7174eb32cf165c355e56aa96d307bfec5b482d33bfcbb3",
	"macos-arm64": "aaf5fc548965bf9d9142951083877ac7391e13d1b4df3d2dbcfd739231250ea3",
}

func editorInstallPrefix() (string, error) {
	if os.Geteuid() == 0 {
		return rootCodeServerPrefix, nil
	}
	usr, err := user.Current()
	if err != nil {
		return "", err
	}
	return filepath.Join(usr.HomeDir, ".local", "lib", "alpamon", "code-server"), nil
}

func installCodeServer(parentCtx context.Context) error {
	ctx, cancel := context.WithTimeout(parentCtx, GetCodeServerConfig().InstallTimeout)
	defer cancel()
	platform := runtime.GOOS
	if platform == "darwin" {
		platform = "macos"
	}
	platform += "-" + runtime.GOARCH
	digest, ok := editorReleaseDigests[platform]
	if !ok {
		return fmt.Errorf("no pinned code-server release for %s", platform)
	}
	tar, err := findEditorTar(tarBinaries)
	if err != nil {
		return err
	}
	prefix, err := editorInstallPrefix()
	if err != nil {
		return err
	}
	archive, err := os.CreateTemp("", "alpamon-editor-*.tar.gz")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(archive.Name()) }()
	defer func() { _ = archive.Close() }()
	asset := "code-server-" + editorReleaseVersion + "-" + platform + ".tar.gz"
	if err := downloadEditorArchive(ctx, "https://github.com/coder/code-server/releases/download/v"+editorReleaseVersion+"/"+asset, digest, archive, http.DefaultTransport); err != nil {
		return err
	}
	if err := prepareEditorReleaseParent(prefix); err != nil {
		return err
	}
	stage, err := os.MkdirTemp(prefix, "release-")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(stage) }()
	install := func() error {
		if _, err := archive.Seek(0, io.SeekStart); err != nil {
			return err
		}
		cmd := exec.CommandContext(ctx, tar, "-xzf", "-", "--no-same-owner", "--strip-components=1", "-C", stage)
		// GNU tar resolves gzip through PATH. Use the same system directories as tar lookup.
		cmd.Env = append(cmd.Environ(), "PATH=/usr/bin:/bin")
		cmd.Stdin = archive
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("extract code-server archive: %w", err)
		}
		return checkEditorRuntime(stage)
	}
	isRoot := os.Geteuid() == 0
	if isRoot {
		err = installRootOwnedCodeServer(stage, 0, 0, install)
	} else {
		err = install()
	}
	if err != nil {
		return err
	}
	return publishEditorRelease(stage, filepath.Join(prefix, "v"+editorReleaseVersion), isRoot)
}

func publishEditorRelease(stage, release string, isRoot bool) error {
	if isRoot {
		if err := verifyEditorRelease(stage); err != nil {
			return err
		}
		marker, err := os.OpenFile(filepath.Join(stage, editorReleaseMarker), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return err
		}
		if err := marker.Close(); err != nil {
			return err
		}
		if err := checkEditorRelease(stage); err != nil {
			return err
		}
		if err := checkEditorRelease(release); err == nil {
			return nil
		}
	} else if err := checkEditorRuntime(release); err == nil {
		return nil
	}
	if err := os.RemoveAll(release); err != nil {
		return fmt.Errorf("remove incomplete code-server release: %w", err)
	}
	return os.Rename(stage, release)
}

func checkEditorRuntime(dir string) error {
	for _, name := range []string{"bin/code-server", "lib/node", "package.json", "out/node/entry.js"} {
		info, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			return err
		}
		executable := name == "bin/code-server" || name == "lib/node"
		if !info.Mode().IsRegular() || (executable && info.Mode().Perm()&0111 == 0) {
			return fmt.Errorf("invalid code-server runtime file: %s", name)
		}
	}
	return nil
}

func downloadEditorArchive(ctx context.Context, location, digest string, dst io.Writer, transport http.RoundTripper) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, location, nil)
	if err != nil {
		return err
	}
	if req.URL.Scheme != "https" {
		return errors.New("code-server download requires HTTPS")
	}
	client := http.Client{Transport: transport, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if req.URL.Scheme != "https" {
			return errors.New("code-server redirect requires HTTPS")
		}
		if len(via) >= 10 {
			return errors.New("too many code-server redirects")
		}
		return nil
	}}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("download code-server (automatic installation requires outbound HTTPS to github.com and release-assets.githubusercontent.com): %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download code-server: HTTP %d (automatic installation requires outbound HTTPS to github.com and release-assets.githubusercontent.com)", resp.StatusCode)
	}
	hash := sha256.New()
	const maxArchiveSize = 512 << 20
	n, err := io.Copy(io.MultiWriter(dst, hash), io.LimitReader(resp.Body, maxArchiveSize+1))
	if n > maxArchiveSize {
		return fmt.Errorf("code-server archive exceeds %d bytes", maxArchiveSize)
	}
	if err != nil {
		return fmt.Errorf("read code-server archive: %w", err)
	}
	if fmt.Sprintf("%x", hash.Sum(nil)) != digest {
		return errors.New("code-server archive SHA-256 mismatch")
	}
	return nil
}

// getCodeServerArgs returns the command line arguments for code-server.
func getCodeServerArgs(socketPath string, userDataDir string) []string {
	return GetCodeServerConfig().ToArgs(socketPath, userDataDir)
}

// getCodeServerEnv returns environment variables for code-server process.
func getCodeServerEnv(homeDir string, includeXDG bool, username string) []string {
	return GetCodeServerConfig().ToEnv(homeDir, includeXDG, username)
}

// validateUserDataDirName rejects a name setupUserDataFiles could not guard.
// That helper opens the name with O_NOFOLLOW, which covers only the last path
// component: IsLocal rejects "" and anything absolute or escaping, the Base
// comparison rejects an embedded separator, and "." would still resolve to the
// home directory itself.
func validateUserDataDirName(name string) error {
	if !filepath.IsLocal(name) || name != filepath.Base(name) || name == "." {
		return fmt.Errorf("invalid user data dir name %q", name)
	}
	return nil
}

// setupUserDataDir creates the user-data-dir with config.yaml and settings.json for code-server.
// If running as root, ownership of created files is changed to the specified user.
func setupUserDataDir(ctx context.Context, homeDir, username, groupname string) (string, error) {
	cfg := GetCodeServerConfig()

	if err := validateUserDataDirName(cfg.UserDataDirName); err != nil {
		return "", err
	}
	userDataDir := filepath.Join(homeDir, cfg.UserDataDirName)

	settingsData, err := cfg.ToSettingsJSON()
	if err != nil {
		return "", fmt.Errorf("failed to marshal settings: %w", err)
	}

	// Create the directories with config.yaml (code-server daemon settings)
	// and User/settings.json (VS Code editor settings).
	if err := setupUserDataFiles(ctx, homeDir, cfg.UserDataDirName, []byte(cfg.ToConfigYAML()), settingsData); err != nil {
		return "", fmt.Errorf("failed to set up user data dir: %w", err)
	}

	if os.Getuid() == 0 {
		if err := chownUserDataDir(ctx, userDataDir, username, groupname); err != nil {
			log.Warn().Err(err).Msg("Failed to change ownership of user data dir.")
		}
	}

	log.Debug().Msgf("Created user data directory at %s with config.", userDataDir)
	return userDataDir, nil
}

// chownUserDataDir changes ownership of the user data directory and its contents.
func chownUserDataDir(ctx context.Context, userDataDir, username, groupname string) error {
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

	return chownTreeNoFollow(ctx, userDataDir, uid, gid)
}

func (m *CodeServerManager) dialSocket() (net.Conn, error) {
	dialer := net.Dialer{Timeout: codeServerReadyDialTimeout}
	conn, err := dialer.DialContext(m.ctx, "unix", m.socketPath)
	if err != nil {
		return nil, err
	}
	if err := validateEditorPeer(conn.(*net.UnixConn), m.procAttr); err != nil {
		warned := false
		m.peerWarnOnce.Do(func() {
			warned = true
			log.Warn().Err(err).Str("session", filepath.Base(filepath.Dir(m.socketPath))).Msg("Editor listener validation failed.")
		})
		if !warned {
			log.Debug().Err(err).Msg("Editor listener validation failed.")
		}
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}

func (m *CodeServerManager) removeSocketDir() {
	m.socketCleanupMu.Lock()
	defer m.socketCleanupMu.Unlock()
	if m.socketPath == "" || m.socketRemoved {
		return
	}
	m.socketRemoved = true
	root := m.socketRoot
	if root == nil {
		return
	}
	if err := root.RemoveAll(filepath.Base(filepath.Dir(m.socketPath))); err != nil {
		log.Warn().Err(err).Msg("Failed to remove editor session directory.")
	}
	_ = root.Close()
	m.socketRoot = nil
}

func editorPassthroughEnv(key string) bool {
	switch key {
	case "ALL_PROXY", "all_proxy", "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "no_proxy", "NODE_EXTRA_CA_CERTS", "SSL_CERT_FILE", "SSL_CERT_DIR", "TZ":
		return true
	}
	return false
}

func editorSocketBase(goos string, euid int, runDir string) string {
	if euid != 0 {
		return filepath.Join(runDir, "editor")
	}
	if goos == "darwin" {
		return "/private/var/alpamon-editor"
	}
	return "/run/alpamon-editor"
}
