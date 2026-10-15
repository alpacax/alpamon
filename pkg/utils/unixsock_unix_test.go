//go:build !windows

package utils

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// shortSocketDir keeps socket paths under sun_path's 104-byte limit, which
// t.TempDir() exceeds on macOS once the private temp subdirectory is added.
func shortSocketDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "us")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

func TestListenUnixPrivate_CreatesSocketWithOwnerOnlyMode(t *testing.T) {
	path := filepath.Join(shortSocketDir(t), "a.sock")

	ln, err := ListenUnixPrivate(path)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })

	fi, err := os.Lstat(path)
	require.NoError(t, err)
	assert.NotZero(t, fi.Mode()&os.ModeSocket, "path is not a socket")
	assert.Equal(t, os.FileMode(0600), fi.Mode().Perm())
}

func TestListenUnixPrivate_LeavesOnlyTheSocketInTheDirectory(t *testing.T) {
	dir := shortSocketDir(t)
	path := filepath.Join(dir, "a.sock")

	ln, err := ListenUnixPrivate(path)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })

	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	assert.Equal(t, []string{"a.sock"}, names)
}

func TestListenUnixPrivate_AcceptsConnectionsOnTheFinalPath(t *testing.T) {
	path := filepath.Join(shortSocketDir(t), "a.sock")
	ln, err := ListenUnixPrivate(path)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })

	client, err := net.Dial("unix", path)
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })
	server, err := ln.Accept()
	require.NoError(t, err)
	t.Cleanup(func() { _ = server.Close() })

	_, isUnix := server.(*net.UnixConn)
	assert.True(t, isUnix, "accepted %T, want *net.UnixConn", server)
}

func TestListenUnixPrivate_ReplacesStaleSocket(t *testing.T) {
	path := filepath.Join(shortSocketDir(t), "a.sock")
	stale, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	require.NoError(t, err)
	stale.SetUnlinkOnClose(false)
	require.NoError(t, stale.Close()) // Leaves the socket file behind, as a crashed agent would.

	ln, err := ListenUnixPrivate(path)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })

	client, err := net.Dial("unix", path)
	require.NoError(t, err)
	_ = client.Close()
}

func TestListenUnixPrivate_RefusesSymlinkAtPath(t *testing.T) {
	dir := shortSocketDir(t)
	target := filepath.Join(dir, "target")
	require.NoError(t, os.WriteFile(target, []byte("keep"), 0600))
	path := filepath.Join(dir, "a.sock")
	require.NoError(t, os.Symlink(target, path))

	_, err := ListenUnixPrivate(path)

	assert.ErrorContains(t, err, "symlink")
	fi, err := os.Lstat(path)
	require.NoError(t, err)
	assert.NotZero(t, fi.Mode()&os.ModeSymlink, "symlink was replaced")
	assert.FileExists(t, target)
}

func TestListenUnixPrivate_RefusesRegularFileAtPath(t *testing.T) {
	path := filepath.Join(shortSocketDir(t), "a.sock")
	require.NoError(t, os.WriteFile(path, []byte("keep"), 0600))

	_, err := ListenUnixPrivate(path)

	assert.ErrorContains(t, err, "non-socket")
	content, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, "keep", string(content))
}

func TestListenUnixPrivate_FailsWhenParentDirectoryIsMissing(t *testing.T) {
	path := filepath.Join(shortSocketDir(t), "missing", "a.sock")

	_, err := ListenUnixPrivate(path)

	assert.Error(t, err)
}

func TestListenUnixPrivate_TooLongTempPathFailsWithoutLeftovers(t *testing.T) {
	base := shortSocketDir(t)
	// A 99-byte dir makes "<dir>/a" (101 bytes) fit sun_path on Linux (107) and macOS (103),
	// while "<dir>/.sock-<1..10 digits>/s" (at least 109 bytes) fits neither.
	dir := filepath.Join(base, strings.Repeat("d", 99-len(base)-1))
	require.NoError(t, os.Mkdir(dir, 0700))
	path := filepath.Join(dir, "a")

	_, err := ListenUnixPrivate(path)

	assert.Error(t, err)
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	assert.Empty(t, entries, "a temp directory or socket was left behind")
}

func TestListenUnixPrivate_CloseRemovesTheSocket(t *testing.T) {
	path := filepath.Join(shortSocketDir(t), "a.sock")
	ln, err := ListenUnixPrivate(path)
	require.NoError(t, err)

	require.NoError(t, ln.Close())

	_, err = os.Stat(path)
	assert.ErrorIs(t, err, os.ErrNotExist)
}

func listenTempSocket(t *testing.T, dir string) string {
	t.Helper()
	tmpPath := filepath.Join(dir, "tmp.sock")
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: tmpPath, Net: "unix"})
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	return tmpPath
}

func TestListenUnixPrivate_CloseKeepsASocketThatReplacedIt(t *testing.T) {
	path := filepath.Join(shortSocketDir(t), "a.sock")
	first, err := ListenUnixPrivate(path)
	require.NoError(t, err)
	require.NoError(t, os.Remove(path))
	second, err := net.Listen("unix", path)
	require.NoError(t, err)
	t.Cleanup(func() { _ = second.Close() })

	require.NoError(t, first.Close())

	_, err = os.Stat(path)
	require.NoError(t, err, "the replacement socket was removed")
	client, err := net.Dial("unix", path)
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })
	accepted, err := second.Accept()
	require.NoError(t, err, "the replacement listener no longer owns the path")
	_ = accepted.Close()
}

// These tests call moveSocketIntoPlace directly to land a file at path after
// RemoveSocket's check, which ListenUnixPrivate gives no hook for.
func TestMoveSocketIntoPlace_KeepsRegularFileThatAppearedAfterTheCheck(t *testing.T) {
	dir := shortSocketDir(t)
	tmpPath := listenTempSocket(t, dir)
	path := filepath.Join(dir, "a.sock")
	require.NoError(t, os.WriteFile(path, []byte("keep"), 0600))

	err := moveSocketIntoPlace(tmpPath, path)

	assert.ErrorIs(t, err, os.ErrExist)
	content, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, "keep", string(content))
}

func TestMoveSocketIntoPlace_KeepsAnotherListenerThatAppearedAfterTheCheck(t *testing.T) {
	dir := shortSocketDir(t)
	tmpPath := listenTempSocket(t, dir)
	path := filepath.Join(dir, "a.sock")
	other, err := net.Listen("unix", path)
	require.NoError(t, err)
	t.Cleanup(func() { _ = other.Close() })

	err = moveSocketIntoPlace(tmpPath, path)

	assert.ErrorIs(t, err, os.ErrExist)
	client, err := net.Dial("unix", path)
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })
	accepted, err := other.Accept()
	require.NoError(t, err, "the other listener no longer owns the path")
	_ = accepted.Close()
}
