//go:build !windows

package utils

import (
	"context"
	"os"
	"os/exec"
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

	// Empty and relative PATH entries must not be resolved against the current
	// directory; only absolute entries are trusted.
	for _, pe := range []string{
		string(os.PathListSeparator) + otherDir, // leading empty entry
		".",                                     // explicit cwd
	} {
		if _, err := LookPath("cwdtool", pe); err == nil {
			t.Errorf("expected non-absolute PATH entry %q not to resolve against cwd, got match", pe)
		}
	}
}

func TestApplyCommandPath(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "mytool")
	if err := os.WriteFile(exe, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatalf("failed to write executable: %v", err)
	}

	// A bare command found in the child PATH is pinned to its resolved path.
	found := exec.CommandContext(context.Background(), "mytool")
	ApplyCommandPath(found, "mytool", dir)
	if found.Err != nil {
		t.Errorf("unexpected error for resolved command: %v", found.Err)
	}
	if found.Path != exe {
		t.Errorf("expected cmd.Path %q, got %q", exe, found.Path)
	}

	// A bare command missing from the child PATH fails here instead of falling
	// back to Alpamon's process PATH.
	missing := exec.CommandContext(context.Background(), "mytool")
	ApplyCommandPath(missing, "mytool", t.TempDir())
	if missing.Err == nil {
		t.Error("expected lookup failure for command missing from child PATH, got nil")
	}
}
