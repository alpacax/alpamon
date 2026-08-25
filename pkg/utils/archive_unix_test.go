//go:build !windows

package utils

import (
	"archive/zip"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCreateZip_IrregularEntriesAreSkipped(t *testing.T) {
	// Short base directory: a unix socket path must fit in sun_path (104
	// bytes on darwin), which t.TempDir() plus this test's name overruns.
	dir, err := os.MkdirTemp("", "z")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	demo := filepath.Join(dir, "demo")
	require.NoError(t, os.MkdirAll(demo, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(demo, "file.txt"), []byte("hi"), 0644))
	require.NoError(t, syscall.Mkfifo(filepath.Join(demo, "fifo"), 0600))
	sock, err := net.Listen("unix", filepath.Join(demo, "sock"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = sock.Close() })

	dest := filepath.Join(dir, "out.zip")
	// The socket used to fail the whole archive and the FIFO used to block
	// os.Open forever, with no context to cancel it.
	requireZip(t, dest, []string{demo}, true)

	r, err := zip.OpenReader(dest)
	require.NoError(t, err)
	defer func() { _ = r.Close() }()

	require.Len(t, r.File, 1)
	assert.Equal(t, "demo/file.txt", r.File[0].Name)
}

func TestCreateZip_ListedIrregularPathIsSkipped(t *testing.T) {
	dir := t.TempDir()

	file := filepath.Join(dir, "file.txt")
	require.NoError(t, os.WriteFile(file, []byte("hi"), 0644))
	fifo := filepath.Join(dir, "fifo")
	require.NoError(t, syscall.Mkfifo(fifo, 0600))

	dest := filepath.Join(dir, "out.zip")
	// The shape a multi-select produces, and the only one that reaches this
	// branch: several paths listed at once, one of them irregular. A lone
	// FIFO is streamed without an archive and never gets here.
	skipped, err := CreateZip(dest, []string{file, fifo}, true)
	require.NoError(t, err)

	r, err := zip.OpenReader(dest)
	require.NoError(t, err)
	defer func() { _ = r.Close() }()

	require.Len(t, r.File, 1)
	assert.Equal(t, "file.txt", r.File[0].Name)

	// The user picked this path by hand, so dropping it without a word would
	// leave them reading an archive that is quietly short one entry.
	require.Len(t, skipped, 1)
	assert.Equal(t, fifo, skipped[0].Path)
	assert.ErrorIs(t, skipped[0].Reason, errNotRegular)
}

func TestCreateZip_UnreadableEntriesAreSkipped(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads a 0000 file whatever its mode says")
	}

	dir := t.TempDir()
	demo := filepath.Join(dir, "demo")
	locked := filepath.Join(demo, "locked")
	secret := filepath.Join(demo, "secret.txt")
	require.NoError(t, os.MkdirAll(locked, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(demo, "readable.txt"), []byte("hi"), 0644))
	require.NoError(t, os.WriteFile(secret, []byte("s"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(locked, "hidden.txt"), []byte("h"), 0644))
	require.NoError(t, os.Chmod(secret, 0000))
	require.NoError(t, os.Chmod(locked, 0000))
	// TempDir cannot delete what it cannot enter, and cleanups run last in first.
	t.Cleanup(func() { _ = os.Chmod(locked, 0755) })

	dest := filepath.Join(dir, "out.zip")
	skipped, err := CreateZip(dest, []string{demo}, true)
	require.NoError(t, err)

	r, err := zip.OpenReader(dest)
	require.NoError(t, err)
	defer func() { _ = r.Close() }()

	require.Len(t, r.File, 1)
	assert.Equal(t, "demo/readable.txt", r.File[0].Name)

	var reported []string
	for _, entry := range skipped {
		reported = append(reported, entry.Path)
		assert.ErrorIs(t, entry.Reason, os.ErrPermission)
	}
	// Walk runs on the resolved root, and on darwin /var is a link to
	// /private/var, so the reported paths carry the resolved prefix.
	resolved, err := filepath.EvalSymlinks(demo)
	require.NoError(t, err)
	// The unreadable directory is reported once, not once per file inside it.
	assert.ElementsMatch(t, []string{
		filepath.Join(resolved, "locked"),
		filepath.Join(resolved, "secret.txt"),
	}, reported)
}
