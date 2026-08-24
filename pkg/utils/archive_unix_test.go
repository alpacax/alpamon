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
	require.NoError(t, CreateZip(dest, []string{demo}, true))

	r, err := zip.OpenReader(dest)
	require.NoError(t, err)
	defer func() { _ = r.Close() }()

	require.Len(t, r.File, 1)
	assert.Equal(t, "demo/file.txt", r.File[0].Name)
}

func TestCreateZip_IrregularPathIsRejected(t *testing.T) {
	dir, err := os.MkdirTemp("", "z")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	fifo := filepath.Join(dir, "fifo")
	require.NoError(t, syscall.Mkfifo(fifo, 0600))

	dest := filepath.Join(dir, "out.zip")
	assert.ErrorContains(t, CreateZip(dest, []string{fifo}, false), "unsupported file type")
}
