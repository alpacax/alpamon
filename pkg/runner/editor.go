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
	"strings"
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

	// External resources
	installScriptURL = "https://code-server.dev/install.sh"

	// Alpacon Editor branding
	brandNameShort       = "Alpacon Editor"
	brandNameLong        = "Alpacon Web Editor"
	brandApplicationName = "alpacon-editor"
	brandGalleryURL      = "https://open-vsx.org/vscode/gallery"
	brandGalleryItemURL  = "https://open-vsx.org/vscode/item"
)

// Common installation paths for code-server
var codeServerPaths = []string{
	"/usr/bin/code-server",
	"/usr/local/bin/code-server",
	"/opt/homebrew/bin/code-server", // macOS Homebrew
}

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
}

func NewCodeServerManager(username, groupname string) (*CodeServerManager, error) {
	var usr *user.User
	var err error

	// On macOS, use current user since credential demotion is not supported
	if runtime.GOOS == "darwin" {
		usr, err = user.Current()
		if err != nil {
			return nil, fmt.Errorf("failed to get current user: %w", err)
		}
		log.Debug().Msg("macOS: skipping credential demotion")
	} else {
		usr, err = user.Lookup(username)
		if err != nil {
			return nil, fmt.Errorf("user %s not found: %w", username, err)
		}

		_, err = user.LookupGroup(groupname)
		if err != nil {
			return nil, fmt.Errorf("group %s not found: %w", groupname, err)
		}
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &CodeServerManager{
		username:  username,
		groupname: groupname,
		homeDir:   usr.HomeDir,
		ctx:       ctx,
		cancel:    cancel,
	}, nil
}

// Start installs (if needed) and starts code-server on an available port.
func (m *CodeServerManager) Start() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.started {
		return nil
	}

	// Restore any orphaned patches from previous crashed sessions
	if err := restoreWorkbenchJS(); err != nil {
		log.Debug().Err(err).Msg("No orphaned workbench.js backup to restore")
	}

	// Check if code-server is installed
	if !isCodeServerInstalled() {
		log.Info().Msg("code-server not found, installing...")
		if err := installCodeServer(); err != nil {
			return fmt.Errorf("code-server installation failed: %w", err)
		}

		if !isCodeServerInstalled() {
			return fmt.Errorf("code-server installation completed but binary not found")
		}
		log.Info().Msg("code-server installed successfully.")
	}

	// Find available port
	port, err := findAvailablePort()
	if err != nil {
		return fmt.Errorf("failed to find available port: %w", err)
	}
	m.port = port

	// Patch product.json for Alpacon Editor branding
	if err := patchProductJSON(); err != nil {
		log.Warn().Err(err).Msg("Failed to patch product.json, continuing with defaults.")
	}

	// Patch workbench.js for Alpacon Editor branding
	if err := patchWorkbenchJS(); err != nil {
		log.Warn().Err(err).Msg("Failed to patch workbench.js, continuing with defaults.")
	}

	// Start code-server process
	cmd, err := startCodeServerProcess(port, m.username, m.groupname, m.homeDir)
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
	// Always try to restore workbench.js, even if process isn't running
	defer func() {
		if err := restoreWorkbenchJS(); err != nil {
			log.Warn().Err(err).Msg("Failed to restore workbench.js")
		}
	}()

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
	_, err := exec.LookPath("code-server")
	if err == nil {
		return true
	}

	for _, path := range codeServerPaths {
		if _, err := os.Stat(path); err == nil {
			return true
		}
	}

	return false
}

func getCodeServerPath() (string, error) {
	path, err := exec.LookPath("code-server")
	if err == nil {
		return path, nil
	}

	for _, p := range codeServerPaths {
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}

	return "", fmt.Errorf("code-server not found")
}

// installCodeServer installs code-server using the official install script.
func installCodeServer() error {
	ctx, cancel := context.WithTimeout(context.Background(), installTimeout)
	defer cancel()

	// Download install script
	resp, err := http.Get(installScriptURL)
	if err != nil {
		return fmt.Errorf("failed to download install script: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to download install script: HTTP %d", resp.StatusCode)
	}

	script, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read install script: %w", err)
	}

	// Execute with sh
	cmd := exec.CommandContext(ctx, "sh")
	cmd.Stdin = bytes.NewReader(script)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("install script failed: %w", err)
	}

	return nil
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
func getCodeServerArgs(port int) []string {
	return []string{
		"--auth", "none",
		"--bind-addr", fmt.Sprintf("127.0.0.1:%d", port),
		"--disable-telemetry",
		"--disable-workspace-trust",
		"--ignore-last-opened",
		"--idle-timeout-seconds", fmt.Sprintf("%d", int(idleTimeout.Seconds())),
	}
}

// findProductJSONPath finds the actual product.json path from code-server installation.
func findProductJSONPath() (string, error) {
	codeServerPath, err := getCodeServerPath()
	if err != nil {
		return "", err
	}

	// Resolve symlink fully to find the installation directory
	realPath, err := filepath.EvalSymlinks(codeServerPath)
	if err != nil {
		realPath = codeServerPath
	}

	// Build candidates based on different installation types
	var candidates []string

	// For Homebrew: look for libexec directory in parent paths
	// realPath might be: .../libexec/out/node/entry.js
	// product.json is at: .../libexec/lib/vscode/product.json
	dir := realPath
	for i := 0; i < 10; i++ { // Walk up to 10 levels
		dir = filepath.Dir(dir)
		if dir == "/" || dir == "." {
			break
		}

		// Check if this directory contains libexec/lib/vscode/product.json
		candidate := filepath.Join(dir, "libexec", "lib", "vscode", "product.json")
		if _, err := os.Stat(candidate); err == nil {
			candidates = append(candidates, candidate)
		}

		// Check if this directory contains lib/vscode/product.json
		candidate = filepath.Join(dir, "lib", "vscode", "product.json")
		if _, err := os.Stat(candidate); err == nil {
			candidates = append(candidates, candidate)
		}
	}

	// Add standard Linux paths
	candidates = append(candidates,
		"/usr/lib/code-server/lib/vscode/product.json",
		"/usr/share/code-server/lib/vscode/product.json",
	)

	for _, candidate := range candidates {
		absPath, err := filepath.Abs(candidate)
		if err != nil {
			continue
		}
		if _, err := os.Stat(absPath); err == nil {
			return absPath, nil
		}
	}

	return "", fmt.Errorf("product.json not found in any known location")
}

// patchProductJSON patches the installed product.json with Alpacon Editor branding.
func patchProductJSON() error {
	productJSONPath, err := findProductJSONPath()
	if err != nil {
		return fmt.Errorf("failed to find product.json: %w", err)
	}

	// Read existing product.json
	data, err := os.ReadFile(productJSONPath)
	if err != nil {
		return fmt.Errorf("failed to read product.json: %w", err)
	}

	// Parse as generic map to preserve all existing fields
	var product map[string]interface{}
	if err := json.Unmarshal(data, &product); err != nil {
		return fmt.Errorf("failed to parse product.json: %w", err)
	}

	// Patch branding fields
	product["nameShort"] = brandNameShort
	product["nameLong"] = brandNameLong
	product["applicationName"] = brandApplicationName

	// Patch extensionsGallery
	gallery := map[string]interface{}{
		"serviceUrl": brandGalleryURL,
		"itemUrl":    brandGalleryItemURL,
	}
	product["extensionsGallery"] = gallery

	// Add trusted domains
	product["linkProtectionTrustedDomains"] = []string{"https://open-vsx.org"}

	// Marshal back to JSON with indentation
	patchedData, err := json.MarshalIndent(product, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal patched product.json: %w", err)
	}

	// Write back to file
	if err := os.WriteFile(productJSONPath, patchedData, 0644); err != nil {
		return fmt.Errorf("failed to write patched product.json: %w", err)
	}

	log.Info().Msgf("Patched product.json at %s with Alpacon Editor branding.", productJSONPath)
	return nil
}

// findWorkbenchJSPath finds the workbench.js path from code-server installation.
func findWorkbenchJSPath() (string, error) {
	codeServerPath, err := getCodeServerPath()
	if err != nil {
		return "", err
	}

	realPath, err := filepath.EvalSymlinks(codeServerPath)
	if err != nil {
		realPath = codeServerPath
	}

	var candidates []string

	dir := realPath
	for i := 0; i < 10; i++ {
		dir = filepath.Dir(dir)
		if dir == "/" || dir == "." {
			break
		}

		// Homebrew path
		candidate := filepath.Join(dir, "libexec", "lib", "vscode", "out", "vs", "code", "browser", "workbench", "workbench.js")
		if _, err := os.Stat(candidate); err == nil {
			candidates = append(candidates, candidate)
		}

		// Standard path
		candidate = filepath.Join(dir, "lib", "vscode", "out", "vs", "code", "browser", "workbench", "workbench.js")
		if _, err := os.Stat(candidate); err == nil {
			candidates = append(candidates, candidate)
		}
	}

	// Standard Linux paths
	candidates = append(candidates,
		"/usr/lib/code-server/lib/vscode/out/vs/code/browser/workbench/workbench.js",
		"/usr/share/code-server/lib/vscode/out/vs/code/browser/workbench/workbench.js",
	)

	for _, candidate := range candidates {
		absPath, err := filepath.Abs(candidate)
		if err != nil {
			continue
		}
		if _, err := os.Stat(absPath); err == nil {
			return absPath, nil
		}
	}

	return "", fmt.Errorf("workbench.js not found in any known location")
}

// patchWorkbenchJS patches the workbench.js with Alpacon Editor branding.
// It creates a backup file (.alpamon.bak) before patching.
func patchWorkbenchJS() error {
	workbenchPath, err := findWorkbenchJSPath()
	if err != nil {
		return fmt.Errorf("failed to find workbench.js: %w", err)
	}

	backupPath := workbenchPath + ".alpamon.bak"

	// Check if already patched (backup exists)
	if _, err := os.Stat(backupPath); err == nil {
		log.Debug().Msgf("workbench.js already patched (backup exists at %s)", backupPath)
		return nil
	}

	// Read original file
	data, err := os.ReadFile(workbenchPath)
	if err != nil {
		return fmt.Errorf("failed to read workbench.js: %w", err)
	}

	// Create backup
	if err := os.WriteFile(backupPath, data, 0644); err != nil {
		return fmt.Errorf("failed to create backup: %w", err)
	}

	// Patch the content
	content := string(data)
	content = strings.ReplaceAll(content, `nameShort:"code-server"`, fmt.Sprintf(`nameShort:"%s"`, brandNameShort))
	content = strings.ReplaceAll(content, `nameLong:"code-server"`, fmt.Sprintf(`nameLong:"%s"`, brandNameLong))

	// Write patched file
	if err := os.WriteFile(workbenchPath, []byte(content), 0644); err != nil {
		// Try to restore backup on failure
		_ = os.Rename(backupPath, workbenchPath)
		return fmt.Errorf("failed to write patched workbench.js: %w", err)
	}

	log.Info().Msgf("Patched workbench.js at %s with Alpacon Editor branding.", workbenchPath)
	return nil
}

// restoreWorkbenchJS restores the original workbench.js from backup.
func restoreWorkbenchJS() error {
	workbenchPath, err := findWorkbenchJSPath()
	if err != nil {
		return fmt.Errorf("failed to find workbench.js: %w", err)
	}

	backupPath := workbenchPath + ".alpamon.bak"

	// Check if backup exists
	if _, err := os.Stat(backupPath); os.IsNotExist(err) {
		log.Debug().Msg("No workbench.js backup found, nothing to restore.")
		return nil
	}

	// Restore from backup
	if err := os.Rename(backupPath, workbenchPath); err != nil {
		return fmt.Errorf("failed to restore workbench.js from backup: %w", err)
	}

	log.Info().Msgf("Restored original workbench.js at %s", workbenchPath)
	return nil
}
