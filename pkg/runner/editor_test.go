package runner

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFindAvailablePort(t *testing.T) {
	port, err := findAvailablePort()
	assert.NoError(t, err, "Failed to find available port")
	assert.True(t, port > 0, "Port should be greater than 0")
	assert.True(t, port <= 65535, "Port should be less than or equal to 65535")
}

func TestFindAvailablePortUnique(t *testing.T) {
	ports := make(map[int]bool)
	for i := 0; i < 10; i++ {
		port, err := findAvailablePort()
		assert.NoError(t, err, "Failed to find available port")
		assert.False(t, ports[port], "Port should be unique across calls")
		ports[port] = true
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

func TestSetupUserDataDir(t *testing.T) {
	// Create a temporary directory for testing
	tempDir := t.TempDir()

	// Call setupUserDataDir
	userDataDir, err := setupUserDataDir(tempDir)
	assert.NoError(t, err, "setupUserDataDir should not error")
	assert.NotEmpty(t, userDataDir, "userDataDir should not be empty")

	// Verify user data directory was created
	cfg := GetCodeServerConfig()
	expectedUserDataDir := filepath.Join(tempDir, cfg.UserDataDirName)
	assert.Equal(t, expectedUserDataDir, userDataDir)
	_, err = os.Stat(userDataDir)
	assert.NoError(t, err, "User data directory should exist")

	// Verify config.yaml was created
	configPath := filepath.Join(userDataDir, "config.yaml")
	configData, err := os.ReadFile(configPath)
	assert.NoError(t, err, "config.yaml should exist and be readable")
	assert.Contains(t, string(configData), "auth: none", "config.yaml should contain auth: none")
	assert.Contains(t, string(configData), "disable-telemetry: true", "config.yaml should contain disable-telemetry")
	assert.Contains(t, string(configData), "disable-update-check: true", "config.yaml should contain disable-update-check")

	// Verify User subdirectory was created
	userDir := filepath.Join(userDataDir, "User")
	_, err = os.Stat(userDir)
	assert.NoError(t, err, "User subdirectory should exist")

	// Verify settings.json was created
	settingsPath := filepath.Join(userDir, "settings.json")
	data, err := os.ReadFile(settingsPath)
	assert.NoError(t, err, "settings.json should exist and be readable")

	// Verify settings.json content
	var settings map[string]interface{}
	err = json.Unmarshal(data, &settings)
	assert.NoError(t, err, "settings.json should be valid JSON")

	assert.Equal(t, cfg.ColorTheme, settings["workbench.colorTheme"], "colorTheme should match config")
	assert.Equal(t, "none", settings["workbench.startupEditor"], "workbench.startupEditor should be 'none'")
	assert.Equal(t, false, settings["workbench.welcomePage.walkthroughs.openOnInstall"], "walkthroughs should be disabled")
	assert.Equal(t, "none", settings["window.restoreWindows"], "window.restoreWindows should be 'none'")
	assert.Equal(t, "off", settings["telemetry.telemetryLevel"], "telemetry should be off")
	assert.Equal(t, false, settings["security.workspace.trust.enabled"], "workspace trust should be disabled")
	assert.Equal(t, "none", settings["update.mode"], "update.mode should be 'none'")
}

func TestSetupUserDataDirIdempotent(t *testing.T) {
	// Create a temporary directory for testing
	tempDir := t.TempDir()

	// Call setupUserDataDir twice
	userDataDir1, err := setupUserDataDir(tempDir)
	assert.NoError(t, err)

	userDataDir2, err := setupUserDataDir(tempDir)
	assert.NoError(t, err)

	// Both calls should return the same path
	assert.Equal(t, userDataDir1, userDataDir2)

	// settings.json should still be valid
	settingsPath := filepath.Join(userDataDir1, "User", "settings.json")
	data, err := os.ReadFile(settingsPath)
	assert.NoError(t, err)

	var settings map[string]interface{}
	err = json.Unmarshal(data, &settings)
	assert.NoError(t, err)
	assert.Equal(t, "none", settings["workbench.startupEditor"])
}
