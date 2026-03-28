package utils

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
)

var (
	systemdAvailable bool
	systemdOnce      sync.Once
)

// HasSystemd returns true if systemd is available and running as PID 1.
func HasSystemd() bool {
	systemdOnce.Do(func() {
		systemdAvailable = detectSystemd()
	})
	return systemdAvailable
}

func detectSystemd() bool {
	if _, err := exec.LookPath("systemctl"); err != nil {
		return false
	}
	// Only Linux uses /proc/1/comm to verify PID 1 is systemd.
	// Other platforms (macOS, etc.) always return false even if
	// systemctl happens to be in PATH (e.g., via Homebrew).
	if runtime.GOOS != "linux" {
		return false
	}
	data, err := os.ReadFile("/proc/1/comm")
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(data)) == "systemd"
}

type alpamonDir struct {
	Path string
	Mode os.FileMode
}

// getAlpamonDirs returns required directories for alpamon.
// On Linux, these match configs/tmpfile.conf and scripts/postinstall.sh:create_directories().
// On macOS, RunDir() differs (/tmp/alpamon instead of /run/alpamon).
func getAlpamonDirs() []alpamonDir {
	return []alpamonDir{
		{ConfigDir(), 0700},
		{DataDir(), 0750},
		{LogDir(), 0750},
		{RunDir(), 0750},
	}
}

// EnsureDirectories creates required alpamon directories with permissions
// and root:root ownership matching configs/tmpfile.conf.
// Replaces systemd-tmpfiles when systemd is unavailable.
func EnsureDirectories() error {
	return ensureDirectoriesWithRoot("")
}

func ensureDirectoriesWithRoot(root string) error {
	for _, d := range getAlpamonDirs() {
		path := d.Path
		if root != "" {
			path = filepath.Join(root, strings.TrimPrefix(path, string(os.PathSeparator)))
		}
		if err := os.MkdirAll(path, d.Mode); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", path, err)
		}
		if err := os.Chmod(path, d.Mode); err != nil {
			return fmt.Errorf("failed to set permissions on %s: %w", path, err)
		}
		// Enforce root:root ownership to match tmpfile.conf.
		// Skip in tests (non-empty root) where we may not be running as root.
		if root == "" {
			if err := os.Chown(path, 0, 0); err != nil {
				return fmt.Errorf("failed to set ownership on %s: %w", path, err)
			}
		}
	}
	return nil
}
