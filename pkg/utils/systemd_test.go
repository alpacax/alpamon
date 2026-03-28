package utils

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestDetectSystemd_Darwin(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("skipping darwin-specific test")
	}
	// On macOS, detectSystemd should always return false
	if detectSystemd() {
		t.Error("detectSystemd() should return false on darwin")
	}
}

func TestEnsureDirectoriesWithRoot(t *testing.T) {
	root := t.TempDir()

	if err := ensureDirectoriesWithRoot(root); err != nil {
		t.Fatalf("ensureDirectoriesWithRoot() error: %v", err)
	}

	for _, d := range getAlpamonDirs() {
		rel := strings.TrimPrefix(d.Path, string(os.PathSeparator))
		path := filepath.Join(root, rel)
		info, err := os.Stat(path)
		if err != nil {
			t.Errorf("directory %s not created: %v", d.Path, err)
			continue
		}
		if !info.IsDir() {
			t.Errorf("%s is not a directory", d.Path)
		}
		if info.Mode().Perm() != d.Mode {
			t.Errorf("%s permissions = %o, want %o", d.Path, info.Mode().Perm(), d.Mode)
		}
	}
}

func TestEnsureDirectoriesWithRoot_Idempotent(t *testing.T) {
	root := t.TempDir()

	// Call twice to verify idempotency
	if err := ensureDirectoriesWithRoot(root); err != nil {
		t.Fatalf("first call error: %v", err)
	}
	if err := ensureDirectoriesWithRoot(root); err != nil {
		t.Fatalf("second call error: %v", err)
	}

	for _, d := range getAlpamonDirs() {
		rel := strings.TrimPrefix(d.Path, string(os.PathSeparator))
		path := filepath.Join(root, rel)
		info, err := os.Stat(path)
		if err != nil {
			t.Errorf("directory %s not found after second call: %v", d.Path, err)
			continue
		}
		if info.Mode().Perm() != d.Mode {
			t.Errorf("%s permissions = %o, want %o", d.Path, info.Mode().Perm(), d.Mode)
		}
	}
}

func TestGetAlpamonDirs_NoSystemDirectories(t *testing.T) {
	// Verify that no directory is a bare system directory like /tmp
	systemDirs := map[string]bool{"/tmp": true, "/var": true, "/etc": true, "/run": true}
	for _, d := range getAlpamonDirs() {
		if systemDirs[d.Path] {
			t.Errorf("getAlpamonDirs() contains bare system directory %q — EnsureDirectories would chmod it", d.Path)
		}
	}
}
