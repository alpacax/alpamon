package runner

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/user"
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

	// External resources
	installScriptURL = "https://code-server.dev/install.sh"
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
	log.Info().
		Int("port", m.port).
		Str("user", m.username).
		Msg("code-server started successfully.")

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

	log.Info().Int("port", m.port).Msg("Stopping code-server...")

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
