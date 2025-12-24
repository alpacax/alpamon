package runner

import (
	"os"
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

func TestFindProductJSONPath(t *testing.T) {
	// This test verifies function behavior
	// If code-server is installed, it should find the product.json path
	if isCodeServerInstalled() {
		path, err := findProductJSONPath()
		assert.NoError(t, err, "Should find product.json when code-server is installed")
		assert.NotEmpty(t, path, "Path should not be empty")
		assert.Contains(t, path, "product.json", "Path should contain product.json")

		// Verify file exists
		_, err = os.Stat(path)
		assert.NoError(t, err, "product.json file should exist at returned path")
	} else {
		_, err := findProductJSONPath()
		assert.Error(t, err, "Should error when code-server is not installed")
	}
}

func TestBrandingConstants(t *testing.T) {
	// Verify branding constants are set correctly
	assert.Equal(t, "Alpacon Editor", brandNameShort)
	assert.Equal(t, "Alpacon Web Editor", brandNameLong)
	assert.Equal(t, "alpacon-editor", brandApplicationName)
	assert.Equal(t, "https://open-vsx.org/vscode/gallery", brandGalleryURL)
	assert.Equal(t, "https://open-vsx.org/vscode/item", brandGalleryItemURL)
}

func TestPatchProductJSON(t *testing.T) {
	if !isCodeServerInstalled() {
		t.Skip("code-server not installed, skipping patch test")
	}

	// Apply the patch
	err := patchProductJSON()
	assert.NoError(t, err, "patchProductJSON should not error")

	// Verify the patch was applied
	path, err := findProductJSONPath()
	assert.NoError(t, err)

	data, err := os.ReadFile(path)
	assert.NoError(t, err)

	assert.Contains(t, string(data), "Alpacon Editor", "product.json should contain Alpacon Editor")
	assert.Contains(t, string(data), "open-vsx.org", "product.json should contain open-vsx.org")

	t.Logf("Patched product.json at: %s", path)
}

func TestFindWorkbenchJSPath(t *testing.T) {
	if !isCodeServerInstalled() {
		t.Skip("code-server not installed, skipping test")
	}

	path, err := findWorkbenchJSPath()
	assert.NoError(t, err, "Should find workbench.js when code-server is installed")
	assert.NotEmpty(t, path, "Path should not be empty")
	assert.Contains(t, path, "workbench.js", "Path should contain workbench.js")

	// Verify file exists
	_, err = os.Stat(path)
	assert.NoError(t, err, "workbench.js file should exist at returned path")

	t.Logf("Found workbench.js at: %s", path)
}

func TestPatchAndRestoreWorkbenchJS(t *testing.T) {
	if !isCodeServerInstalled() {
		t.Skip("code-server not installed, skipping patch test")
	}

	path, err := findWorkbenchJSPath()
	assert.NoError(t, err)

	// Read original content
	originalData, err := os.ReadFile(path)
	assert.NoError(t, err)

	// Apply the patch
	err = patchWorkbenchJS()
	assert.NoError(t, err, "patchWorkbenchJS should not error")

	// Verify the patch was applied
	patchedData, err := os.ReadFile(path)
	assert.NoError(t, err)
	assert.Contains(t, string(patchedData), "Alpacon Editor", "workbench.js should contain Alpacon Editor after patch")

	// Verify backup was created
	backupPath := path + ".alpamon.bak"
	_, err = os.Stat(backupPath)
	assert.NoError(t, err, "Backup file should exist")

	// Restore original
	err = restoreWorkbenchJS()
	assert.NoError(t, err, "restoreWorkbenchJS should not error")

	// Verify restore
	restoredData, err := os.ReadFile(path)
	assert.NoError(t, err)
	assert.Equal(t, originalData, restoredData, "Restored content should match original")

	// Verify backup was removed
	_, err = os.Stat(backupPath)
	assert.True(t, os.IsNotExist(err), "Backup file should be removed after restore")

	t.Logf("Successfully tested patch and restore of workbench.js at: %s", path)
}
