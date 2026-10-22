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
		isRoot    bool
		euid      uint32
		nobodyUID int
		nobodyGID int
		wantOwner []uint32
		wantUID   int
		wantGID   int
	}{
		{"root allows root and nobody and chowns to nobody", true, 0, 65534, 65533, []uint32{0, 65534}, 65534, 65533},
		{"root keeps macOS nobody's uid past MaxInt32", true, 0, 4294967294, 4294967294, []uint32{0, 4294967294}, 4294967294, 4294967294},
		{"non-root allows only itself and never chowns", false, 1000, 0, 0, []uint32{1000}, -1, -1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			allowed, uid, gid := tunnelSocketDirPolicy(tc.isRoot, tc.euid, tc.nobodyUID, tc.nobodyGID)

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
