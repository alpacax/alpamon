package utils

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadEnvironmentFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "environment")
	content := "# comment\n\nPATH=/usr/bin\nLANG=\"en_US.UTF-8\"\n  HTTP_PROXY = http://proxy:3128  \nnot-an-assignment\n=novalue\n"
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600), "write")

	env := map[string]string{}
	loadEnvironmentFile(path, env)

	want := map[string]string{
		"PATH":       "/usr/bin",
		"LANG":       "en_US.UTF-8",
		"HTTP_PROXY": "http://proxy:3128",
	}
	assert.Len(t, env, len(want), "expected %d entries, got %v", len(want), env)
	for key, value := range want {
		assert.Equal(t, value, env[key], key)
	}
}

func TestLoadEnvironmentFile_MissingFileIsANoOp(t *testing.T) {
	env := map[string]string{"KEEP": "1"}
	loadEnvironmentFile(filepath.Join(t.TempDir(), "absent"), env)
	assert.Len(t, env, 1, "expected env untouched, got %v", env)
	assert.Equal(t, "1", env["KEEP"], "expected env untouched, got %v", env)
}

// Vendor defaults load first so an admin copy overrides them, which is what the
// EnvironmentFilePaths order encodes.
func TestLoadEnvironmentFile_LaterFileOverrides(t *testing.T) {
	dir := t.TempDir()
	vendor := filepath.Join(dir, "usr-etc")
	admin := filepath.Join(dir, "etc")
	require.NoError(t, os.WriteFile(vendor, []byte("PATH=/vendor\nONLY_VENDOR=1\n"), 0o600), "write")
	require.NoError(t, os.WriteFile(admin, []byte("PATH=/admin\n"), 0o600), "write")

	env := map[string]string{}
	for _, path := range []string{vendor, admin} {
		loadEnvironmentFile(path, env)
	}

	assert.Equal(t, "/admin", env["PATH"], "want the admin value")
	assert.Equal(t, "1", env["ONLY_VENDOR"], "a vendor-only entry must survive, got %v", env)
}

// Tumbleweed and the transactional variants ship /usr/etc/environment and no
// /etc/environment at all, so both paths are read, vendor first.
func TestEnvironmentFilePaths_Linux(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skipf("no /etc/environment equivalent on %s", runtime.GOOS)
	}

	paths := EnvironmentFilePaths()
	assert.Equal(t, []string{"/usr/etc/environment", "/etc/environment"}, paths, "expected the vendor path first")
}
