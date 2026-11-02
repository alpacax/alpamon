//go:build !windows

package file

import (
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type cleanupErrorReader struct {
	swap func() error
	err  error
}

func (r *cleanupErrorReader) Read([]byte) (int, error) {
	if r.swap != nil {
		r.err = r.swap()
		r.swap = nil
	}
	return 0, io.ErrUnexpectedEOF
}

func TestWriteFileAs_CleanupLeavesNonEmptyUnrelatedDirectory(t *testing.T) {
	dir := t.TempDir()
	userParent := filepath.Join(dir, "requester")
	otherParent := filepath.Join(dir, "unrelated")
	require.NoError(t, os.Mkdir(userParent, 0700))
	require.NoError(t, os.Mkdir(otherParent, 0700))
	unrelated := filepath.Join(otherParent, "new")
	require.NoError(t, os.MkdirAll(filepath.Join(unrelated, "output"), 0700))
	source := &cleanupErrorReader{swap: func() error {
		if err := os.Rename(userParent, userParent+"-old"); err != nil {
			return err
		}
		return os.Symlink(otherParent, userParent)
	}}
	err := writeFileAs(t.Context(), filepath.Join(userParent, "new", "output"), source, &syscall.SysProcAttr{})
	require.Error(t, err)
	require.NoError(t, source.err)
	assert.DirExists(t, unrelated, "cleanup removes only empty directories, one rmdir at a time")
}

func TestWriteFileAs_CleanupKeepsNonEmptyCreatedDirectory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "new", "nested", "output")
	kept := filepath.Join(filepath.Dir(path), "keep")
	source := &cleanupErrorReader{swap: func() error {
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			return err
		}
		return os.WriteFile(kept, []byte("keep"), 0644)
	}}
	err := writeFileAs(t.Context(), path, source, &syscall.SysProcAttr{})
	require.ErrorIs(t, err, io.ErrUnexpectedEOF)
	require.NoError(t, source.err)
	got, err := os.ReadFile(kept)
	require.NoError(t, err)
	assert.Equal(t, "keep", string(got))
	assert.DirExists(t, filepath.Dir(path))
}

func TestRemoveCreatedDirsAsRequester_ContinuesPastMissingDirectory(t *testing.T) {
	root := t.TempDir()
	removeCreatedDirsAsRequester(t.Context(), filepath.Join(root, "gone"), root, &syscall.SysProcAttr{})
	_, err := os.Stat(root)
	assert.ErrorIs(t, err, os.ErrNotExist)
}

func TestRemoveCreatedDirsAsRequester_StopsAtUnsearchableDirectory(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory search permission")
	}
	base := t.TempDir()
	createdRoot := filepath.Join(base, "created")
	locked := filepath.Join(createdRoot, "locked")
	require.NoError(t, os.MkdirAll(locked, 0755))
	require.NoError(t, os.Chmod(locked, 0))
	t.Cleanup(func() { _ = os.Chmod(locked, 0755) })
	removeCreatedDirsAsRequester(t.Context(), filepath.Join(locked, "missing"), createdRoot, &syscall.SysProcAttr{})
	assert.DirExists(t, locked)
	assert.DirExists(t, createdRoot)
}

func TestRemoveCreatedDirsAsRequester_IgnoresRelativePath(t *testing.T) {
	base := t.TempDir()
	t.Chdir(base)
	require.NoError(t, os.MkdirAll(filepath.Join("relative", "dir"), 0755))
	original := fileHelperCommand
	t.Cleanup(func() { fileHelperCommand = original })
	ran := false
	fileHelperCommand = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		ran = true
		return original(ctx, name, args...)
	}
	removeCreatedDirsAsRequester(t.Context(), filepath.Join("relative", "dir"), "relative", &syscall.SysProcAttr{})
	assert.False(t, ran)
	assert.DirExists(t, filepath.Join("relative", "dir"))
}

func TestRemoveCreatedDirsAsRequester_RunsAfterCancellation(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "new")
	leaf := filepath.Join(root, "nested")
	require.NoError(t, os.MkdirAll(leaf, 0755))
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	removeCreatedDirsAsRequester(ctx, leaf, root, &syscall.SysProcAttr{})
	_, err := os.Stat(root)
	assert.ErrorIs(t, err, os.ErrNotExist)
	assert.DirExists(t, base)
}

func TestRemoveCreatedDirsAsRequester_RemovesPartiallyCreatedParents(t *testing.T) {
	base := t.TempDir()
	createdRoot := filepath.Join(base, "created")
	require.NoError(t, os.Mkdir(createdRoot, 0755))
	removeCreatedDirsAsRequester(t.Context(), filepath.Join(createdRoot, "missing", "deeper"), createdRoot, &syscall.SysProcAttr{})
	_, err := os.Stat(createdRoot)
	assert.ErrorIs(t, err, os.ErrNotExist)
	assert.DirExists(t, base)
}

func TestRequesterCleanupCommandsHaveDetachedDeadline(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	original := fileHelperCommand
	t.Cleanup(func() { fileHelperCommand = original })
	var commands []string
	fileHelperCommand = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		commands = append(commands, name)
		assert.NoError(t, ctx.Err())
		deadline, ok := ctx.Deadline()
		require.True(t, ok)
		assert.InDelta(t, 30, time.Until(deadline).Seconds(), 1)
		return exec.CommandContext(ctx, "/bin/sh", "-c", "exit 1")
	}
	attr := &syscall.SysProcAttr{}
	removeAsRequester(ctx, filepath.Join(t.TempDir(), "output"), attr)
	root := filepath.Join(t.TempDir(), "new")
	removeCreatedDirsAsRequester(ctx, root, root, attr)
	assert.Equal(t, []string{"/bin/rm", "/bin/rmdir", "/bin/sh"}, commands)
}
