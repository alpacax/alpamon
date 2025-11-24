package config

import (
	"os"
	"testing"
)

func TestPoolConfigDefaults(t *testing.T) {
	// Test that default pool values are set correctly when not configured
	config := Config{}
	_, settings := validateConfig(config, "/ws/test/")

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

	_, settings := validateConfig(config, "/ws/test/")

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
	defer os.Remove(tmpfile.Name())

	if _, err := tmpfile.Write([]byte(content)); err != nil {
		t.Fatal(err)
	}
	if err := tmpfile.Close(); err != nil {
		t.Fatal(err)
	}

	// Load the config
	settings := LoadConfig([]string{tmpfile.Name()}, "/ws/test/")

	if settings.PoolMaxWorkers != 30 {
		t.Errorf("Expected PoolMaxWorkers to be 30 from INI, got %d", settings.PoolMaxWorkers)
	}

	if settings.PoolQueueSize != 300 {
		t.Errorf("Expected PoolQueueSize to be 300 from INI, got %d", settings.PoolQueueSize)
	}
}