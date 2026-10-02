package utils

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDetectSystemd_Darwin(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("skipping darwin-specific test")
	}
	// On macOS, detectSystemd should always return false
	assert.False(t, detectSystemd(), "detectSystemd() should return false on darwin")
}

func TestEnsureDirectoriesWithRoot(t *testing.T) {
	if runtime.GOOS == "windows" {
		// Windows os.Stat reports a synthetic Mode().Perm() based on the
		// read-only attribute, not the Unix mode bits we set. The chmod
		// call itself still runs via ensureDirectoriesWithRoot, but the
		// assertion below is Unix-only and would falsely fail here.
		t.Skip("Unix file-mode assertions; Windows does not expose Unix perm bits.")
	}
	root := t.TempDir()

	require.NoError(t, ensureDirectoriesWithRoot(root), "ensureDirectoriesWithRoot() error")

	for _, d := range getAlpamonDirs() {
		rel := d.Path
		if vol := filepath.VolumeName(rel); vol != "" {
			rel = rel[len(vol):]
		}
		rel = strings.TrimPrefix(rel, string(os.PathSeparator))
		path := filepath.Join(root, rel)
		info, err := os.Stat(path)
		if !assert.NoError(t, err, "directory %s not created", d.Path) {
			continue
		}
		assert.True(t, info.IsDir(), "%s is not a directory", d.Path)
		assert.Equal(t, d.Mode, info.Mode().Perm(), "%s permissions", d.Path)
	}
}

func TestEnsureDirectoriesWithRoot_Idempotent(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix file-mode assertions; Windows does not expose Unix perm bits.")
	}
	root := t.TempDir()

	// Call twice to verify idempotency
	require.NoError(t, ensureDirectoriesWithRoot(root), "first call error")
	require.NoError(t, ensureDirectoriesWithRoot(root), "second call error")

	for _, d := range getAlpamonDirs() {
		rel := d.Path
		if vol := filepath.VolumeName(rel); vol != "" {
			rel = rel[len(vol):]
		}
		rel = strings.TrimPrefix(rel, string(os.PathSeparator))
		path := filepath.Join(root, rel)
		info, err := os.Stat(path)
		if !assert.NoError(t, err, "directory %s not found after second call", d.Path) {
			continue
		}
		assert.Equal(t, d.Mode, info.Mode().Perm(), "%s permissions", d.Path)
	}
}

func TestGetAlpamonDirs_NoSystemDirectories(t *testing.T) {
	// Verify that no directory is a bare system directory like /tmp
	systemDirs := map[string]bool{"/tmp": true, "/var": true, "/etc": true, "/run": true}
	for _, d := range getAlpamonDirs() {
		assert.False(t, systemDirs[d.Path], "getAlpamonDirs() contains bare system directory %q: EnsureDirectories would chmod it", d.Path)
	}
}
