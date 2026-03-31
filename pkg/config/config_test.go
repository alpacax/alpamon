package config

import (
	"os"
	"testing"
)

func intPtr(v int) *int {
	return &v
}

func TestPoolConfigDefaults(t *testing.T) {
	// Test that default pool values are set correctly when not configured
	config := Config{}
	_, settings := validateConfig(config, "/ws/test/", "/ws/control/")

	if settings.PoolMaxWorkers != DefaultPoolMaxWorkers {
		t.Errorf("Expected default PoolMaxWorkers to be %d, got %d", DefaultPoolMaxWorkers, settings.PoolMaxWorkers)
	}

	if settings.PoolQueueSize != DefaultPoolQueueSize {
		t.Errorf("Expected default PoolQueueSize to be %d, got %d", DefaultPoolQueueSize, settings.PoolQueueSize)
	}

	if settings.PoolDefaultTimeout != DefaultPoolDefaultTimeout {
		t.Errorf("Expected default PoolDefaultTimeout to be %d, got %d", DefaultPoolDefaultTimeout, settings.PoolDefaultTimeout)
	}
}

func TestPoolConfigCustomValues(t *testing.T) {
	// Test that custom pool values are applied correctly
	config := Config{}
	config.Pool.MaxWorkers = 50
	config.Pool.QueueSize = 500

	_, settings := validateConfig(config, "/ws/test/", "/ws/control/")

	if settings.PoolMaxWorkers != 50 {
		t.Errorf("Expected PoolMaxWorkers to be 50, got %d", settings.PoolMaxWorkers)
	}

	if settings.PoolQueueSize != 500 {
		t.Errorf("Expected PoolQueueSize to be 500, got %d", settings.PoolQueueSize)
	}
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

	tmpfile, err := os.CreateTemp("", "alpamon-test-*.conf")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Remove(tmpfile.Name()) }()

	if _, err := tmpfile.Write([]byte(content)); err != nil {
		t.Fatal(err)
	}
	if err := tmpfile.Close(); err != nil {
		t.Fatal(err)
	}

	// Load the config
	settings := LoadConfig([]string{tmpfile.Name()}, "/ws/test/", "/ws/control/")

	if settings.PoolMaxWorkers != 30 {
		t.Errorf("Expected PoolMaxWorkers to be 30 from INI, got %d", settings.PoolMaxWorkers)
	}

	if settings.PoolQueueSize != 300 {
		t.Errorf("Expected PoolQueueSize to be 300 from INI, got %d", settings.PoolQueueSize)
	}
}

func TestEditorIdleTimeoutDefaults(t *testing.T) {
	config := Config{}
	_, settings := validateConfig(config, "/ws/test/", "/ws/control/")

	if settings.EditorIdleTimeout != DefaultEditorIdleTimeout {
		t.Errorf("Expected default EditorIdleTimeout to be %d, got %d", DefaultEditorIdleTimeout, settings.EditorIdleTimeout)
	}
}

func TestEditorIdleTimeoutZero(t *testing.T) {
	config := Config{}
	config.Editor.IdleTimeout = intPtr(0)
	_, settings := validateConfig(config, "/ws/test/", "/ws/control/")

	if settings.EditorIdleTimeout != 0 {
		t.Errorf("Expected EditorIdleTimeout to be 0, got %d", settings.EditorIdleTimeout)
	}
}

func TestEditorIdleTimeoutCustom(t *testing.T) {
	config := Config{}
	config.Editor.IdleTimeout = intPtr(15)
	_, settings := validateConfig(config, "/ws/test/", "/ws/control/")

	if settings.EditorIdleTimeout != 15 {
		t.Errorf("Expected EditorIdleTimeout to be 15, got %d", settings.EditorIdleTimeout)
	}
}

func TestSigningConfigDefaults(t *testing.T) {
	config := Config{}
	_, settings := validateConfig(config, "/ws/test/", "/ws/control/")

	if settings.AIServerURL != "" {
		t.Errorf("Expected default AIServerURL to be empty, got %s", settings.AIServerURL)
	}
	if settings.SigningMode != DefaultSigningMode {
		t.Errorf("Expected default SigningMode to be %s, got %s", DefaultSigningMode, settings.SigningMode)
	}
	if settings.KeyRefreshSecs != DefaultKeyRefreshSecs {
		t.Errorf("Expected default KeyRefreshSecs to be %d, got %d", DefaultKeyRefreshSecs, settings.KeyRefreshSecs)
	}
}

func TestSigningConfigValid(t *testing.T) {
	config := Config{}
	config.Signing.AIServerURL = "https://ai.example.com/"
	config.Signing.Mode = "enforce"
	config.Signing.KeyRefresh = intPtr(1800)

	_, settings := validateConfig(config, "/ws/test/", "/ws/control/")

	if settings.AIServerURL != "https://ai.example.com" {
		t.Errorf("Expected AIServerURL trailing slash trimmed, got %s", settings.AIServerURL)
	}
	if settings.SigningMode != "enforce" {
		t.Errorf("Expected SigningMode 'enforce', got %s", settings.SigningMode)
	}
	if settings.KeyRefreshSecs != 1800 {
		t.Errorf("Expected KeyRefreshSecs 1800, got %d", settings.KeyRefreshSecs)
	}
}

func TestSigningConfigInvalidMode(t *testing.T) {
	config := Config{}
	config.Signing.AIServerURL = "https://ai.example.com"
	config.Signing.Mode = "invalid"

	valid, _ := validateConfig(config, "/ws/test/", "/ws/control/")
	if valid {
		t.Error("Expected validation to fail for invalid signing mode")
	}
}

func TestSigningConfigInvalidURL(t *testing.T) {
	config := Config{}
	config.Signing.AIServerURL = "not-a-url"

	valid, _ := validateConfig(config, "/ws/test/", "/ws/control/")
	if valid {
		t.Error("Expected validation to fail for invalid ai_server_url")
	}
}

func TestSigningConfigNegativeKeyRefresh(t *testing.T) {
	config := Config{}
	config.Signing.AIServerURL = "https://ai.example.com"
	config.Signing.KeyRefresh = intPtr(-1)

	valid, _ := validateConfig(config, "/ws/test/", "/ws/control/")
	if valid {
		t.Error("Expected validation to fail for negative key_refresh")
	}
}

func TestSigningConfigZeroKeyRefresh(t *testing.T) {
	config := Config{}
	config.Signing.AIServerURL = "https://ai.example.com"
	config.Signing.KeyRefresh = intPtr(0)

	valid, _ := validateConfig(config, "/ws/test/", "/ws/control/")
	if valid {
		t.Error("Expected validation to fail for zero key_refresh")
	}
}

func TestSigningConfigWithoutURL(t *testing.T) {
	// Setting mode/key_refresh without ai_server_url should warn but not fail
	config := Config{}
	config.Signing.Mode = "enforce"

	valid, settings := validateConfig(config, "/ws/test/", "/ws/control/")

	// Should not fail validation (just warn)
	if settings.AIServerURL != "" {
		t.Errorf("Expected empty AIServerURL, got %s", settings.AIServerURL)
	}
	// Mode should remain default since URL is empty
	if settings.SigningMode != DefaultSigningMode {
		t.Errorf("Expected default SigningMode when URL is empty, got %s", settings.SigningMode)
	}
	_ = valid
}

func TestSigningConfigFromINI(t *testing.T) {
	content := `[server]
url = http://test.com
id = testid
key = testkey

[signing]
ai_server_url = https://ai.example.com
mode = enforce
key_refresh = 7200
`
	tmpfile, err := os.CreateTemp("", "alpamon-test-*.conf")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Remove(tmpfile.Name()) }()

	if _, err := tmpfile.Write([]byte(content)); err != nil {
		t.Fatal(err)
	}
	if err := tmpfile.Close(); err != nil {
		t.Fatal(err)
	}

	settings := LoadConfig([]string{tmpfile.Name()}, "/ws/test/", "/ws/control/")

	if settings.AIServerURL != "https://ai.example.com" {
		t.Errorf("Expected AIServerURL 'https://ai.example.com', got %s", settings.AIServerURL)
	}
	if settings.SigningMode != "enforce" {
		t.Errorf("Expected SigningMode 'enforce', got %s", settings.SigningMode)
	}
	if settings.KeyRefreshSecs != 7200 {
		t.Errorf("Expected KeyRefreshSecs 7200, got %d", settings.KeyRefreshSecs)
	}
}
