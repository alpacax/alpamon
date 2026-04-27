package utils

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
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
	Path  string
	Mode  os.FileMode
	Group string // desired group owner; empty means root
}

// getAlpamonDirs returns required directories for alpamon.
// On Linux, these match configs/tmpfile.conf and scripts/postinstall.sh:create_directories().
// RunDir() varies by platform and privilege: /run/alpamon (Linux root),
// /var/run/alpamon (macOS root), or /tmp/alpamon (non-root on any platform).
func getAlpamonDirs() []alpamonDir {
	return []alpamonDir{
		{ConfigDir(), 0700, ""},
		{DataDir(), 0750, ""},
		{LogDir(), 0750, ""},
		// RunDir is group-owned by "alpamon" so plugin processes in that group
		// can traverse the directory and connect to the log socket.
		{RunDir(), 0750, "alpamon"},
	}
}

// EnsureDirectories creates required alpamon directories with permissions
// matching configs/tmpfile.conf. Replaces systemd-tmpfiles when systemd is unavailable.
func EnsureDirectories() error {
	return ensureDirectoriesWithRoot("")
}

func ensureDirectoriesWithRoot(root string) error {
	for _, d := range getAlpamonDirs() {
		path := d.Path
		if root != "" {
			// Convert absolute path to relative for test root overlay.
			// On Unix: strip leading "/" (e.g., /etc/alpamon → etc/alpamon)
			// On Windows: strip volume + separator (e.g., C:\ProgramData → ProgramData)
			rel := path
			if vol := filepath.VolumeName(rel); vol != "" {
				rel = rel[len(vol):]
			}
			rel = strings.TrimPrefix(rel, string(os.PathSeparator))
			path = filepath.Join(root, rel)
		}
		if err := os.MkdirAll(path, d.Mode); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", path, err)
		}
		if err := os.Chmod(path, d.Mode); err != nil {
			return fmt.Errorf("failed to set permissions on %s: %w", path, err)
		}
		// Enforce ownership to match tmpfile.conf.
		// Skip in tests (non-empty root) and on Windows (no Unix ownership).
		if root == "" && runtime.GOOS != "windows" {
			gid := 0
			if d.Group != "" {
				gid = lookupGroupID(d.Group)
			}
			if err := os.Chown(path, 0, gid); err != nil {
				return fmt.Errorf("failed to set ownership on %s: %w", path, err)
			}
		}
	}
	return nil
}

// lookupGroupID returns the GID for the named group, or 0 if not found.
func lookupGroupID(name string) int {
	grp, err := user.LookupGroup(name)
	if err != nil {
		return 0
	}
	gid, err := strconv.Atoi(grp.Gid)
	if err != nil {
		return 0
	}
	return gid
}
