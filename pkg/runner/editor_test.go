package runner

import (
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
	args := getCodeServerArgs(8080)

	assert.Contains(t, args, "--auth", "Args should contain --auth")
	assert.Contains(t, args, "none", "Auth should be none")
	assert.Contains(t, args, "--bind-addr", "Args should contain --bind-addr")
	assert.Contains(t, args, "127.0.0.1:8080", "Bind address should be 127.0.0.1:8080")
	assert.Contains(t, args, "--disable-telemetry", "Args should contain --disable-telemetry")
}

func TestGetCodeServerArgsDifferentPorts(t *testing.T) {
	testCases := []struct {
		port     int
		expected string
	}{
		{8080, "127.0.0.1:8080"},
		{3000, "127.0.0.1:3000"},
		{65535, "127.0.0.1:65535"},
	}

	for _, tc := range testCases {
		args := getCodeServerArgs(tc.port)
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
