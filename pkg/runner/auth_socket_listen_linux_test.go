//go:build linux

package runner

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func shortAuthSocketPath(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "as")
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, os.RemoveAll(dir)) })
	return filepath.Join(dir, "a.sock")
}

func assertAuthListenerAccepts(t *testing.T, listener net.Listener, path string) {
	t.Helper()
	t.Cleanup(func() { assert.NoError(t, listener.Close()) })
	info, err := os.Lstat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), info.Mode().Perm())
	client, err := net.Dial("unix", path)
	require.NoError(t, err)
	defer func() { _ = client.Close() }()
	server, err := listener.Accept()
	require.NoError(t, err)
	assert.NoError(t, server.Close())
}

func TestListenUnixLabeledDisabled(t *testing.T) {
	path := shortAuthSocketPath(t)
	writes := 0
	listener, err := listenUnixLabeled(path, sockcreateLabeler{
		enabled: func() bool { return false },
		write: func(string) error {
			writes++
			return nil
		},
	})
	require.NoError(t, err)
	assert.Equal(t, 0, writes)
	assertAuthListenerAccepts(t, listener, path)
}

func TestListenUnixLabeledSuccess(t *testing.T) {
	path := shortAuthSocketPath(t)
	var writes []string
	var tids []int
	listener, err := listenUnixLabeled(path, sockcreateLabeler{
		enabled: func() bool { return true },
		write: func(context string) error {
			writes = append(writes, context)
			tids = append(tids, unix.Gettid())
			return nil
		},
		listen: listenUnixPrivate,
	})
	require.NoError(t, err)
	assert.Equal(t, []string{authSocketContext, ""}, writes)
	require.Len(t, tids, 2)
	assert.Equal(t, tids[0], tids[1])
	assertAuthListenerAccepts(t, listener, path)
}

func TestListenUnixLabeledSetFails(t *testing.T) {
	path := shortAuthSocketPath(t)
	var writes []string
	listener, err := listenUnixLabeled(path, sockcreateLabeler{
		enabled: func() bool { return true },
		write: func(context string) error {
			writes = append(writes, context)
			return syscall.EINVAL
		},
		listen: listenUnixPrivate,
	})
	require.NoError(t, err)
	assert.Equal(t, []string{authSocketContext}, writes)
	assertAuthListenerAccepts(t, listener, path)
}

func TestListenUnixLabeledClearFails(t *testing.T) {
	path := shortAuthSocketPath(t)
	var writes []string
	listener, err := listenUnixLabeled(path, sockcreateLabeler{
		enabled: func() bool { return true },
		write: func(context string) error {
			writes = append(writes, context)
			if context == "" {
				return syscall.EACCES
			}
			return nil
		},
		listen: listenUnixPrivate,
	})
	require.NoError(t, err)
	assert.Equal(t, []string{authSocketContext, ""}, writes)
	assertAuthListenerAccepts(t, listener, path)
}

func TestListenUnixLabeledListenFails(t *testing.T) {
	path := shortAuthSocketPath(t)
	var writes []string
	created := make(chan error, 1)
	listener, err := listenUnixLabeled(path, sockcreateLabeler{
		enabled: func() bool { return true },
		write: func(context string) error {
			writes = append(writes, context)
			return nil
		},
		listen: func(_, address string) (net.Listener, error) {
			created <- leaveSocketAt(address)
			return nil, errors.New("labeled listen failed")
		},
	})
	require.NoError(t, <-created)
	require.NoError(t, err)
	assert.Equal(t, []string{authSocketContext, ""}, writes)
	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.NotZero(t, info.Mode()&os.ModeSocket)
	assertAuthListenerAccepts(t, listener, path)
}

// leaveSocketAt closes a listener on path without unlinking it, as a failed listen can.
func leaveSocketAt(path string) error {
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return err
	}
	ln.SetUnlinkOnClose(false)
	return ln.Close()
}
