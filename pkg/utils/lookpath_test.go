//go:build !windows

package utils

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLookPath(t *testing.T) {
	dir := t.TempDir()
	otherDir := t.TempDir()

	exe := filepath.Join(dir, "mytool")
	if err := os.WriteFile(exe, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatalf("failed to write executable: %v", err)
	}

	nonExe := filepath.Join(dir, "notool")
	if err := os.WriteFile(nonExe, []byte("data"), 0o644); err != nil {
		t.Fatalf("failed to write non-executable: %v", err)
	}

	pathEnv := otherDir + string(os.PathListSeparator) + dir

	// Found in the second PATH entry.
	got, err := LookPath("mytool", pathEnv)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != exe {
		t.Errorf("expected %q, got %q", exe, got)
	}

	// A non-executable regular file is not a match.
	if _, err := LookPath("notool", pathEnv); err == nil {
		t.Error("expected error for non-executable file, got nil")
	}

	// Missing executable yields an error.
	if _, err := LookPath("missing", pathEnv); err == nil {
		t.Error("expected error for missing executable, got nil")
	}

	// A path with a separator is returned unchanged without searching.
	abs := "/bin/sh"
	if got, err := LookPath(abs, pathEnv); err != nil || got != abs {
		t.Errorf("expected %q unchanged, got %q (err %v)", abs, got, err)
	}

	// Empty PATH entries must not be resolved against the current directory.
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get cwd: %v", err)
	}
	cwdExe := filepath.Join(cwd, "cwdtool")
	if err := os.WriteFile(cwdExe, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatalf("failed to write cwd executable: %v", err)
	}
	defer func() { _ = os.Remove(cwdExe) }()

	// PATH with a leading empty entry ("" + sep + ...) must not match cwdtool.
	emptyFirst := string(os.PathListSeparator) + otherDir
	if _, err := LookPath("cwdtool", emptyFirst); err == nil {
		t.Error("expected empty PATH entry not to resolve against cwd, got match")
	}
}
