//go:build !windows

package runner

import (
	"os"
	"path/filepath"
	"strconv"
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

	err := secureTunnelSocketDir(d, nil, uint32(os.Geteuid()))

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

	err := secureTunnelSocketDir(link, nil, uint32(os.Geteuid()))

	require.Error(t, err)
	assert.ErrorContains(t, err, "symlink")
	fi, statErr := os.Stat(target)
	require.NoError(t, statErr)
	assert.Equal(t, os.FileMode(0777), fi.Mode().Perm())
}

func TestSecureTunnelSocketDir_RefusesRegularFile(t *testing.T) {
	f := filepath.Join(t.TempDir(), "file")
	require.NoError(t, os.WriteFile(f, nil, 0600))

	err := secureTunnelSocketDir(f, nil, uint32(os.Geteuid()))

	assert.ErrorContains(t, err, "not a directory")
}

func TestSecureTunnelSocketDir_RefusesDirectoryOwnedBySomeoneElse(t *testing.T) {
	d := filepath.Join(t.TempDir(), "tunnels")
	makeOpenDir(t, d)

	err := secureTunnelSocketDir(d, nil, uint32(os.Geteuid())+1)

	require.Error(t, err)
	fi, statErr := os.Stat(d)
	require.NoError(t, statErr)
	assert.Equal(t, os.FileMode(0777), fi.Mode().Perm())
}

func TestTunnelSocketDirPolicy(t *testing.T) {
	linuxNobody := &syscall.Credential{Uid: 65534, Gid: 65533}
	macNobody := &syscall.Credential{Uid: 4294967294, Gid: 4294967294}
	cases := []struct {
		name       string
		daemon     *syscall.Credential
		euid       uint32
		wantOwners []uint32
		wantOwner  *syscall.Credential
	}{
		{name: "a daemon credential allows root and the daemon and hands the dir over", daemon: linuxNobody, euid: 0, wantOwners: []uint32{0, 65534}, wantOwner: linuxNobody},
		{name: "a daemon credential keeps macOS nobody's uid past MaxInt32", daemon: macNobody, euid: 0, wantOwners: []uint32{0, 4294967294}, wantOwner: macNobody},
		{name: "no daemon credential allows only the current user and keeps the owner", daemon: nil, euid: 1000, wantOwners: []uint32{1000}, wantOwner: nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			allowed, owner := tunnelSocketDirPolicy(tc.daemon, tc.euid)

			assert.Equal(t, tc.wantOwners, allowed)
			assert.Same(t, tc.wantOwner, owner)
		})
	}
}

func TestCredentialIDs_KeepsMacOSNobodyIntact(t *testing.T) {
	if strconv.IntSize < 64 {
		t.Skip("4294967294 does not fit a 32-bit int")
	}

	uid, gid, err := credentialIDs(&syscall.Credential{Uid: 4294967294, Gid: 4294967294})

	require.NoError(t, err)
	assert.Equal(t, 4294967294, uid)
	assert.Equal(t, 4294967294, gid)
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

	err := secureTunnelSocketDir(d, &syscall.Credential{Uid: 65534, Gid: 65534}, 0)

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

	err := secureTunnelSocketDir(d, &syscall.Credential{}, 0)

	require.Error(t, err)
	assert.Equal(t, uint32(65534), dirOwner(t, d))
}
