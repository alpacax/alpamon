package runner

import (
	"net"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFindAvailablePort(t *testing.T) {
	port, err := findAvailablePort()
	assert.NoError(t, err, "Failed to find available port")
	assert.True(t, port > 0, "Port should be greater than 0")
	assert.True(t, port <= 65535, "Port should be less than or equal to 65535")
}

func TestFindAvailablePortRepeated(t *testing.T) {
	for range 10 {
		port, err := findAvailablePort()
		assert.NoError(t, err, "Failed to find available port")
		assert.True(t, port > 0 && port <= 65535, "Port should be in valid range")
	}
}

func TestGetCodeServerArgs(t *testing.T) {
	userDataDir := "/tmp/test-user-data"
	args := getCodeServerArgs(8080, userDataDir)

	assert.Contains(t, args, "--config", "Args should contain --config")
	assert.Contains(t, args, "--user-data-dir", "Args should contain --user-data-dir")
	assert.Contains(t, args, userDataDir, "Args should contain user data dir path")
	assert.Contains(t, args, "--bind-addr", "Args should contain --bind-addr")
	assert.Contains(t, args, "127.0.0.1:8080", "Bind address should be 127.0.0.1:8080")
	assert.Contains(t, args, "--idle-timeout-seconds", "Args should contain --idle-timeout-seconds")
}

func TestGetCodeServerArgsDifferentPorts(t *testing.T) {
	userDataDir := "/tmp/test-user-data"
	testCases := []struct {
		port     int
		expected string
	}{
		{8080, "127.0.0.1:8080"},
		{3000, "127.0.0.1:3000"},
		{65535, "127.0.0.1:65535"},
	}

	for _, tc := range testCases {
		args := getCodeServerArgs(tc.port, userDataDir)
		assert.Contains(t, args, tc.expected, "Bind address should match port")
	}
}

func TestIsCodeServerInstalled(t *testing.T) {
	// This test just verifies the function doesn't panic
	// Result depends on whether code-server is installed on the system
	result := isCodeServerInstalled()
	assert.IsType(t, true, result, "Should return a boolean")
}

func TestGetCodeServerPath(t *testing.T) {
	// This test verifies function behavior
	// If code-server is installed, it should return a path
	// If not, it should return an error
	path, err := getCodeServerPath()
	if isCodeServerInstalled() {
		assert.NoError(t, err, "Should not error when code-server is installed")
		assert.NotEmpty(t, path, "Path should not be empty when code-server is installed")
	} else {
		assert.Error(t, err, "Should error when code-server is not installed")
	}
}

// TestSetupUserDataDirRejectsUnsafeDirName covers the precondition the
// O_NOFOLLOW helpers rely on: the name must be one usable path component.
func TestSetupUserDataDirRejectsUnsafeDirName(t *testing.T) {
	cfg := GetCodeServerConfig()
	original := cfg.UserDataDirName
	t.Cleanup(func() { cfg.UserDataDirName = original })

	for _, name := range []string{"", ".", "..", filepath.Join("..", "escape"), filepath.Join(".config", "editor")} {
		t.Run(name, func(t *testing.T) {
			cfg.UserDataDirName = name

			_, err := setupUserDataDir(t.TempDir(), "", "")

			assert.ErrorContains(t, err, "invalid user data dir name")
		})
	}
}

// TestToSettingsJSONGolden locks the settings.json wire format so future
// edits to codeServerSettings can't silently change the emitted output.
func TestToSettingsJSONGolden(t *testing.T) {
	c := &CodeServerConfig{
		ColorTheme:                "Default Dark Modern",
		StartupEditor:             "none",
		RestoreWindows:            "none",
		WindowTitle:               "Alpamon Editor",
		TelemetryLevel:            "off",
		UpdateMode:                "none",
		DisableWorkspaceTrust:     true,
		DisableWelcomeWalkthrough: true,
	}
	want := `{
  "workbench.colorTheme": "Default Dark Modern",
  "window.title": "Alpamon Editor",
  "telemetry.telemetryLevel": "off",
  "workbench.startupEditor": "none",
  "window.restoreWindows": "none",
  "update.mode": "none",
  "security.workspace.trust.enabled": false,
  "workbench.welcomePage.walkthroughs.openOnInstall": false
}`
	got, err := c.ToSettingsJSON()
	assert.NoError(t, err)
	assert.Equal(t, want, string(got))
}

// TestWaitForReadyChecksTheExitBeforeTheDial: another process can grab the port
// the moment code-server dies, and a dial that answers is then not our server.
func TestWaitForReadyChecksTheExitBeforeTheDial(t *testing.T) {
	ln, err := net.Listen("tcp", net.JoinHostPort(loopbackHost, "0"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })

	_, port, err := net.SplitHostPort(ln.Addr().String())
	require.NoError(t, err)

	m := &CodeServerManager{}
	m.port, err = strconv.Atoi(port)
	require.NoError(t, err)

	waitDone := make(chan struct{})
	close(waitDone)

	assert.ErrorContains(t, m.waitForReady(waitDone), "exited unexpectedly")
}
