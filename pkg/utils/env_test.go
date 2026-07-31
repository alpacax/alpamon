package utils

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestLoadEnvironmentFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "environment")
	content := "# comment\n\nPATH=/usr/bin\nLANG=\"en_US.UTF-8\"\n  HTTP_PROXY = http://proxy:3128  \nnot-an-assignment\n=novalue\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	env := map[string]string{}
	loadEnvironmentFile(path, env)

	want := map[string]string{
		"PATH":       "/usr/bin",
		"LANG":       "en_US.UTF-8",
		"HTTP_PROXY": "http://proxy:3128",
	}
	if len(env) != len(want) {
		t.Errorf("expected %d entries, got %v", len(want), env)
	}
	for key, value := range want {
		if env[key] != value {
			t.Errorf("%s = %q, want %q", key, env[key], value)
		}
	}
}

func TestLoadEnvironmentFile_MissingFileIsANoOp(t *testing.T) {
	env := map[string]string{"KEEP": "1"}
	loadEnvironmentFile(filepath.Join(t.TempDir(), "absent"), env)
	if len(env) != 1 || env["KEEP"] != "1" {
		t.Errorf("expected env untouched, got %v", env)
	}
}

// Vendor defaults load first so an admin copy overrides them, which is what the
// EnvironmentFilePaths order encodes.
func TestLoadEnvironmentFile_LaterFileOverrides(t *testing.T) {
	dir := t.TempDir()
	vendor := filepath.Join(dir, "usr-etc")
	admin := filepath.Join(dir, "etc")
	if err := os.WriteFile(vendor, []byte("PATH=/vendor\nONLY_VENDOR=1\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := os.WriteFile(admin, []byte("PATH=/admin\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	env := map[string]string{}
	for _, path := range []string{vendor, admin} {
		loadEnvironmentFile(path, env)
	}

	if env["PATH"] != "/admin" {
		t.Errorf("PATH = %q, want the admin value", env["PATH"])
	}
	if env["ONLY_VENDOR"] != "1" {
		t.Errorf("a vendor-only entry must survive, got %v", env)
	}
}

// Tumbleweed and the transactional variants ship /usr/etc/environment and no
// /etc/environment at all, so both paths are read, vendor first.
func TestEnvironmentFilePaths_Linux(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skipf("no /etc/environment equivalent on %s", runtime.GOOS)
	}

	paths := EnvironmentFilePaths()
	if len(paths) != 2 || paths[0] != "/usr/etc/environment" || paths[1] != "/etc/environment" {
		t.Errorf("expected the vendor path first, got %v", paths)
	}
}
