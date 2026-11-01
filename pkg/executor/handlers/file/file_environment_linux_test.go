//go:build linux

package file

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFileReaderDoesNotInheritAgentEnvironment(t *testing.T) {
	dir := t.TempDir()
	const secretName = "ALPAMON_HELPER_SENTINEL"
	t.Setenv(secretName, "synthetic-service-secret")
	// A harmless stand-in observes only this test's synthetic environment value.
	require.NoError(t, os.WriteFile(filepath.Join(dir, "cat"), []byte("#!/bin/sh\nprintf '%s' \"$ALPAMON_HELPER_SENTINEL\"\n"), 0700))
	t.Setenv("PATH", dir)
	input := filepath.Join(dir, "input")
	require.NoError(t, os.WriteFile(input, nil, 0600))
	// Select the same subprocess branch as a demoted requester without requiring root.
	reader, _, err := readFileAs(t.Context(), input, &syscall.SysProcAttr{})
	require.NoError(t, err)
	defer reader.Close()
	got, err := io.ReadAll(reader)
	require.NoError(t, err)
	assert.Empty(t, string(got), "a file helper must not inherit the agent service's secrets")
}

func TestFileWriterDoesNotInheritAgentEnvironment(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("ALPAMON_HELPER_SENTINEL", "synthetic-value")
	// The selected shell records the child's environment in the requested file.
	require.NoError(t, os.WriteFile(filepath.Join(dir, "sh"), []byte("#!/bin/sh\nprintf '%s' \"$ALPAMON_HELPER_SENTINEL\" > \""+filepath.Join(dir, "observed")+"\"\n"), 0700))
	t.Setenv("PATH", dir)
	require.NoError(t, writeFileAs(t.Context(), filepath.Join(dir, "output"), strings.NewReader("content"), &syscall.SysProcAttr{}))
	got, err := os.ReadFile(filepath.Join(dir, "observed"))
	require.NoError(t, err)
	assert.Empty(t, got)
}

func TestFileRemovalDoesNotInheritAgentEnvironment(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("ALPAMON_HELPER_SENTINEL", "synthetic-value")
	require.NoError(t, os.WriteFile(filepath.Join(dir, "rm"), []byte("#!/bin/sh\nprintf '%s' \"$ALPAMON_HELPER_SENTINEL\" > \""+filepath.Join(dir, "observed")+"\"\n"), 0700))
	t.Setenv("PATH", dir)
	removeAsRequester(t.Context(), filepath.Join(dir, "output"), &syscall.SysProcAttr{})
	got, err := os.ReadFile(filepath.Join(dir, "observed"))
	require.NoError(t, err)
	assert.Empty(t, got)
}

func TestFileCleanupDoesNotInheritAgentEnvironment(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("ALPAMON_HELPER_SENTINEL", "synthetic-value")
	// The stand-in rmdir records its environment and fails, so the walk also runs its sh check.
	observed := filepath.Join(dir, "observed")
	for _, name := range []string{"rmdir", "sh"} {
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\nprintf '%s' \"$ALPAMON_HELPER_SENTINEL\" >> \""+observed+"\"\nexit 1\n"), 0700))
	}
	t.Setenv("PATH", dir)
	created := filepath.Join(dir, "created")
	removeCreatedDirsAsRequester(t.Context(), created, created, &syscall.SysProcAttr{})
	got, err := os.ReadFile(observed)
	require.NoError(t, err)
	assert.Empty(t, got)
}
