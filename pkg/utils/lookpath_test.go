//go:build !windows

package utils

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLookPath(t *testing.T) {
	dir := t.TempDir()
	otherDir := t.TempDir()

	exe := filepath.Join(dir, "mytool")
	require.NoError(t, os.WriteFile(exe, []byte("#!/bin/sh\n"), 0o755), "failed to write executable")

	nonExe := filepath.Join(dir, "notool")
	require.NoError(t, os.WriteFile(nonExe, []byte("data"), 0o644), "failed to write non-executable")

	pathEnv := otherDir + string(os.PathListSeparator) + dir

	// Found in the second PATH entry.
	got, err := LookPath("mytool", pathEnv)
	require.NoError(t, err)
	assert.Equal(t, exe, got)

	// A non-executable regular file is not a match.
	_, err = LookPath("notool", pathEnv)
	assert.Error(t, err, "expected error for non-executable file")

	// Missing executable yields an error.
	_, err = LookPath("missing", pathEnv)
	assert.Error(t, err, "expected error for missing executable")

	// A path with a separator is returned unchanged without searching.
	abs := "/bin/sh"
	got, err = LookPath(abs, pathEnv)
	assert.NoError(t, err)
	assert.Equal(t, abs, got, "expected path unchanged")

	// Empty PATH entries must not be resolved against the current directory.
	cwd, err := os.Getwd()
	require.NoError(t, err, "failed to get cwd")
	cwdExe := filepath.Join(cwd, "cwdtool")
	require.NoError(t, os.WriteFile(cwdExe, []byte("#!/bin/sh\n"), 0o755), "failed to write cwd executable")
	defer func() { _ = os.Remove(cwdExe) }()

	// Empty and relative PATH entries must not be resolved against the current
	// directory; only absolute entries are trusted.
	for _, pe := range []string{
		string(os.PathListSeparator) + otherDir, // leading empty entry
		".",                                     // explicit cwd
	} {
		_, err := LookPath("cwdtool", pe)
		assert.Error(t, err, "expected non-absolute PATH entry %q not to resolve against cwd, got match", pe)
	}
}

func TestApplyCommandPath(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "mytool")
	require.NoError(t, os.WriteFile(exe, []byte("#!/bin/sh\n"), 0o755), "failed to write executable")

	// A bare command found in the child PATH is pinned to its resolved path.
	found := exec.CommandContext(context.Background(), "mytool")
	ApplyCommandPath(found, "mytool", dir)
	assert.NoError(t, found.Err, "unexpected error for resolved command")
	assert.Equal(t, exe, found.Path, "cmd.Path")

	// A bare command missing from the child PATH fails here instead of falling
	// back to Alpamon's process PATH.
	missing := exec.CommandContext(context.Background(), "mytool")
	ApplyCommandPath(missing, "mytool", t.TempDir())
	assert.Error(t, missing.Err, "expected lookup failure for command missing from child PATH")
}
