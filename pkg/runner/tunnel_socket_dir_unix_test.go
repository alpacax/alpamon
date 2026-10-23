//go:build !windows

package runner

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func makeOpenDir(t *testing.T, path string) {
	t.Helper()
	require.NoError(t, os.Mkdir(path, 0777))
	require.NoError(t, os.Chmod(path, 0777))
}

func TestSecureTunnelSocketDir_TightensAPreMadeOpenDirectory(t *testing.T) {
	d := filepath.Join(t.TempDir(), "tunnels")
	makeOpenDir(t, d)

	err := secureTunnelSocketDir(d, -1, -1, uint32(os.Geteuid()))

	require.NoError(t, err)
	fi, err := os.Stat(d)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0700), fi.Mode().Perm())
}

func TestSecureTunnelSocketDir_RefusesSymlink(t *testing.T) {
	parent := t.TempDir()
	target := filepath.Join(parent, "target")
	makeOpenDir(t, target)
	link := filepath.Join(parent, "link")
	require.NoError(t, os.Symlink(target, link))

	err := secureTunnelSocketDir(link, -1, -1, uint32(os.Geteuid()))

	require.Error(t, err)
	assert.ErrorContains(t, err, "symlink")
	fi, statErr := os.Stat(target)
	require.NoError(t, statErr)
	assert.Equal(t, os.FileMode(0777), fi.Mode().Perm())
}

func TestSecureTunnelSocketDir_RefusesRegularFile(t *testing.T) {
	f := filepath.Join(t.TempDir(), "file")
	require.NoError(t, os.WriteFile(f, nil, 0600))

	err := secureTunnelSocketDir(f, -1, -1, uint32(os.Geteuid()))

	assert.ErrorContains(t, err, "not a directory")
}

func TestSecureTunnelSocketDir_RefusesDirectoryOwnedBySomeoneElse(t *testing.T) {
	d := filepath.Join(t.TempDir(), "tunnels")
	makeOpenDir(t, d)

	err := secureTunnelSocketDir(d, -1, -1, uint32(os.Geteuid())+1)

	require.Error(t, err)
	fi, statErr := os.Stat(d)
	require.NoError(t, statErr)
	assert.Equal(t, os.FileMode(0777), fi.Mode().Perm())
}

func TestTunnelSocketDirPolicy(t *testing.T) {
	cases := []struct {
		name      string
		hasDaemon bool
		euid      uint32
		daemonUID int
		daemonGID int
		wantOwner []uint32
		wantUID   int
		wantGID   int
	}{
		{
			name:      "root allows root and nobody and chowns to nobody",
			hasDaemon: true, euid: 0, daemonUID: 65534, daemonGID: 65533,
			wantOwner: []uint32{0, 65534}, wantUID: 65534, wantGID: 65533,
		},
		{
			name:      "root keeps macOS nobody's uid past MaxInt32",
			hasDaemon: true, euid: 0, daemonUID: 4294967294, daemonGID: 4294967294,
			wantOwner: []uint32{0, 4294967294}, wantUID: 4294967294, wantGID: 4294967294,
		},
		{
			name:      "non-root allows only itself and never chowns",
			hasDaemon: false, euid: 1000,
			wantOwner: []uint32{1000}, wantUID: -1, wantGID: -1,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			allowed, uid, gid := tunnelSocketDirPolicy(tc.hasDaemon, tc.euid, tc.daemonUID, tc.daemonGID)

			assert.Equal(t, tc.wantOwner, allowed)
			assert.Equal(t, tc.wantUID, uid)
			assert.Equal(t, tc.wantGID, gid)
		})
	}
}

func dirOwner(t *testing.T, path string) uint32 {
	t.Helper()
	fi, err := os.Stat(path)
	require.NoError(t, err)
	st, ok := fi.Sys().(*syscall.Stat_t)
	require.True(t, ok)
	return st.Uid
}

func TestSecureTunnelSocketDir_ChownsToRequestedOwnerWhenRoot(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("chown to another uid needs root")
	}
	d := filepath.Join(t.TempDir(), "tunnels")
	makeOpenDir(t, d)

	err := secureTunnelSocketDir(d, 65534, 65534, 0)

	require.NoError(t, err)
	assert.Equal(t, uint32(65534), dirOwner(t, d))
}

func TestSecureTunnelSocketDir_RefusesForeignDirWithoutChowningIt(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("chown to another uid needs root")
	}
	d := filepath.Join(t.TempDir(), "tunnels")
	makeOpenDir(t, d)
	require.NoError(t, os.Chown(d, 65534, 65534))

	err := secureTunnelSocketDir(d, 0, 0, 0)

	require.Error(t, err)
	assert.Equal(t, uint32(65534), dirOwner(t, d))
}
