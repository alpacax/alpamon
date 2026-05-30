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
}
