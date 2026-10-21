//go:build !windows

package utils

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// shortSocketDir keeps socket paths under sun_path's 104-byte limit, which
// t.TempDir() can exceed on macOS.
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

func TestListenUnixPrivate_AcceptsConnections(t *testing.T) {
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

func TestListenUnixPrivate_RefusesWhatIsNotASocketAtPath(t *testing.T) {
	tests := []struct {
		name    string
		place   func(t *testing.T, dir, path string)
		wantErr string
	}{
		{
			name: "symlink",
			place: func(t *testing.T, dir, path string) {
				target := filepath.Join(dir, "target")
				require.NoError(t, os.WriteFile(target, []byte("keep"), 0600))
				require.NoError(t, os.Symlink(target, path))
			},
			wantErr: "symlink",
		},
		{
			name: "regular file",
			place: func(t *testing.T, _, path string) {
				require.NoError(t, os.WriteFile(path, []byte("keep"), 0600))
			},
			wantErr: "non-socket",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := shortSocketDir(t)
			path := filepath.Join(dir, "a.sock")
			tt.place(t, dir, path)
			before, err := os.Lstat(path)
			require.NoError(t, err)

			_, err = ListenUnixPrivate(path)

			assert.ErrorContains(t, err, tt.wantErr)
			after, err := os.Lstat(path)
			require.NoError(t, err)
			assert.True(t, os.SameFile(before, after), "the file at path was replaced")
			content, err := os.ReadFile(path) // Follows the symlink to its target.
			require.NoError(t, err)
			assert.Equal(t, "keep", string(content))
		})
	}
}

func TestListenUnixPrivate_FailsWhenParentDirectoryIsMissing(t *testing.T) {
	path := filepath.Join(shortSocketDir(t), "missing", "a.sock")

	_, err := ListenUnixPrivate(path)

	assert.Error(t, err)
}

func TestListenUnixPrivate_ServesALongPath(t *testing.T) {
	base := shortSocketDir(t)
	// "<99-byte dir>/a" is 101 bytes, longer than most socket paths but inside sun_path on Linux (107) and macOS (103).
	dir := filepath.Join(base, strings.Repeat("d", 99-len(base)-1))
	require.NoError(t, os.Mkdir(dir, 0700))
	path := filepath.Join(dir, "a")

	ln, err := ListenUnixPrivate(path)

	require.NoError(t, err)
	fi, err := os.Lstat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), fi.Mode().Perm())
	client, err := net.Dial("unix", path)
	require.NoError(t, err)
	_ = client.Close()
	require.NoError(t, ln.Close())
	_, err = os.Stat(path)
	assert.ErrorIs(t, err, os.ErrNotExist)
}

func TestListenUnixPrivate_ModeIsNeverWiderThanOwnerOnlyUnderAnyUmask(t *testing.T) {
	for _, umask := range []int{0, 0o022, 0o277} {
		t.Run(fmt.Sprintf("umask %04o", umask), func(t *testing.T) {
			path := filepath.Join(shortSocketDir(t), "a.sock") // Made before the umask, which could close the directory to its owner.
			old := syscall.Umask(umask)
			t.Cleanup(func() { syscall.Umask(old) })

			ln, err := ListenUnixPrivate(path)

			require.NoError(t, err)
			t.Cleanup(func() { _ = ln.Close() })
			fi, err := os.Lstat(path)
			require.NoError(t, err)
			assert.Zero(t, fi.Mode().Perm()&^0600, "mode %04o is wider than 0600", fi.Mode().Perm())
		})
	}
}

func TestListenUnixPrivate_CloseRemovesTheSocket(t *testing.T) {
	path := filepath.Join(shortSocketDir(t), "a.sock")
	ln, err := ListenUnixPrivate(path)
	require.NoError(t, err)

	require.NoError(t, ln.Close())

	_, err = os.Stat(path)
	assert.ErrorIs(t, err, os.ErrNotExist)
}

func TestListenUnixPrivate_SecondCloseReportsClosedListener(t *testing.T) {
	path := filepath.Join(shortSocketDir(t), "a.sock")
	ln, err := ListenUnixPrivate(path)
	require.NoError(t, err)
	require.NoError(t, ln.Close())

	err = ln.Close()

	assert.ErrorIs(t, err, net.ErrClosed)
	_, err = os.Stat(path)
	assert.ErrorIs(t, err, os.ErrNotExist)
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

// These tests call listenPrivateAt directly to land a file at path after
// RemoveSocket's check, which ListenUnixPrivate gives no hook for.
func TestListenPrivateAt_KeepsRegularFileThatAppearedAfterTheCheck(t *testing.T) {
	path := filepath.Join(shortSocketDir(t), "a.sock")
	require.NoError(t, os.WriteFile(path, []byte("keep"), 0644))

	_, err := listenPrivateAt(path)

	assert.ErrorIs(t, err, unix.EADDRINUSE)
	fi, err := os.Lstat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0644), fi.Mode().Perm())
	content, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, "keep", string(content))
}

func TestListenPrivateAt_KeepsAnotherListenerThatAppearedAfterTheCheck(t *testing.T) {
	path := filepath.Join(shortSocketDir(t), "a.sock")
	other, err := net.Listen("unix", path)
	require.NoError(t, err)
	t.Cleanup(func() { _ = other.Close() })

	_, err = listenPrivateAt(path)

	assert.ErrorIs(t, err, unix.EADDRINUSE)
	client, err := net.Dial("unix", path)
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })
	accepted, err := other.Accept()
	require.NoError(t, err, "the other listener no longer owns the path")
	_ = accepted.Close()
}
