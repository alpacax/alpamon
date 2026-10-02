package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func intPtr(v int) *int {
	return &v
}

func TestPoolConfigDefaults(t *testing.T) {
	// Test that default pool values are set correctly when not configured
	config := Config{}
	_, settings := validateConfig(config, "/ws/test/", "/ws/control/")

	assert.Equal(t, DefaultPoolMaxWorkers, settings.PoolMaxWorkers, "Expected default PoolMaxWorkers")

	assert.Equal(t, DefaultPoolQueueSize, settings.PoolQueueSize, "Expected default PoolQueueSize")

	assert.Equal(t, DefaultPoolDefaultTimeout, settings.PoolDefaultTimeout, "Expected default PoolDefaultTimeout")
}

func TestPoolConfigCustomValues(t *testing.T) {
	// Test that custom pool values are applied correctly
	config := Config{}
	config.Pool.MaxWorkers = 50
	config.Pool.QueueSize = 500

	_, settings := validateConfig(config, "/ws/test/", "/ws/control/")

	assert.Equal(t, 50, settings.PoolMaxWorkers, "Expected PoolMaxWorkers to be 50")

	assert.Equal(t, 500, settings.PoolQueueSize, "Expected PoolQueueSize to be 500")
}

func TestPoolConfigFromINI(t *testing.T) {
	// Create a temporary config file
	content := `[server]
url = http://test.com
id = testid
key = testkey

[pool]
max_workers = 30
queue_size = 300
`

	confPath := filepath.Join(t.TempDir(), "alpamon-test.conf")
	require.NoError(t, os.WriteFile(confPath, []byte(content), 0o600))

	// Load the config
	settings := LoadConfig([]string{confPath}, "/ws/test/", "/ws/control/")

	assert.Equal(t, 30, settings.PoolMaxWorkers, "Expected PoolMaxWorkers to be 30 from INI")

	assert.Equal(t, 300, settings.PoolQueueSize, "Expected PoolQueueSize to be 300 from INI")
}

func TestEditorIdleTimeoutDefaults(t *testing.T) {
	config := Config{}
	_, settings := validateConfig(config, "/ws/test/", "/ws/control/")

	assert.Equal(t, DefaultEditorIdleTimeout, settings.EditorIdleTimeout, "Expected default EditorIdleTimeout")
}

func TestEditorIdleTimeoutZero(t *testing.T) {
	config := Config{}
	config.Editor.IdleTimeout = intPtr(0)
	_, settings := validateConfig(config, "/ws/test/", "/ws/control/")

	assert.Equal(t, 0, settings.EditorIdleTimeout, "Expected EditorIdleTimeout to be 0")
}

func TestEditorIdleTimeoutCustom(t *testing.T) {
	config := Config{}
	config.Editor.IdleTimeout = intPtr(15)
	_, settings := validateConfig(config, "/ws/test/", "/ws/control/")

	assert.Equal(t, 15, settings.EditorIdleTimeout, "Expected EditorIdleTimeout to be 15")
}

func TestMaxDownloadBytesDefault(t *testing.T) {
	config := Config{}
	_, settings := validateConfig(config, "/ws/test/", "/ws/control/")

	assert.Equal(t, int64(0), settings.MaxDownloadBytes, "Expected default MaxDownloadBytes to be 0 (unlimited)")
}

func TestMaxDownloadBytesConfigured(t *testing.T) {
	config := Config{}
	config.File.MaxDownloadBytes = 1024 * 1024 * 100 // 100 MiB
	_, settings := validateConfig(config, "/ws/test/", "/ws/control/")

	assert.Equal(t, int64(1024*1024*100), settings.MaxDownloadBytes, "Expected MaxDownloadBytes")
}

func TestIncludeVirtualInterfacesDefault(t *testing.T) {
	config := Config{}
	_, settings := validateConfig(config, "/ws/test/", "/ws/control/")

	assert.Empty(t, settings.IncludeVirtualInterfaces,
		"no virtual interface is reported unless the configuration names one")
}

func TestIncludeVirtualInterfacesDropsUnusablePatterns(t *testing.T) {
	config := Config{}
	config.Interface.IncludeVirtual = []string{" br0 ", "", "veth*", "[unclosed"}

	_, settings := validateConfig(config, "/ws/test/", "/ws/control/")

	assert.Equal(t, []string{"br0", "veth*"}, settings.IncludeVirtualInterfaces,
		"surrounding space is trimmed, and empty and malformed patterns are dropped")
}

func TestIncludeVirtualInterfacesFromINI(t *testing.T) {
	content := `[server]
url = http://test.com
id = testid
key = testkey

[interface]
include_virtual = br0, veth*, docker0
exclude_virtual_from_inventory = true
`

	confPath := filepath.Join(t.TempDir(), "alpamon-test.conf")
	require.NoError(t, os.WriteFile(confPath, []byte(content), 0o600))

	settings := LoadConfig([]string{confPath}, "/ws/test/", "/ws/control/")

	assert.Equal(t, []string{"br0", "veth*", "docker0"}, settings.IncludeVirtualInterfaces,
		"the list is read as comma-separated names and globs")
	assert.True(t, settings.ExcludeVirtualFromInventory)
}

func TestExcludeVirtualFromInventoryDefault(t *testing.T) {
	config := Config{}
	_, settings := validateConfig(config, "/ws/test/", "/ws/control/")

	assert.False(t, settings.ExcludeVirtualFromInventory,
		"the interface inventory reports what it always has unless the setting asks otherwise")
}
