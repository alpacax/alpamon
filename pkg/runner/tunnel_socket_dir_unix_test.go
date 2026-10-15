//go:build !windows

package runner

import (
	"os"
	"path/filepath"
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

	err := secureTunnelSocketDir(d, uint32(os.Geteuid()))

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

	err := secureTunnelSocketDir(link, uint32(os.Geteuid()))

	require.Error(t, err)
	assert.ErrorContains(t, err, "symlink")
	fi, statErr := os.Stat(target)
	require.NoError(t, statErr)
	assert.Equal(t, os.FileMode(0777), fi.Mode().Perm())
}

func TestSecureTunnelSocketDir_RefusesRegularFile(t *testing.T) {
	f := filepath.Join(t.TempDir(), "file")
	require.NoError(t, os.WriteFile(f, nil, 0600))

	err := secureTunnelSocketDir(f, uint32(os.Geteuid()))

	assert.ErrorContains(t, err, "not a directory")
}

func TestSecureTunnelSocketDir_RefusesDirectoryOwnedBySomeoneElse(t *testing.T) {
	d := filepath.Join(t.TempDir(), "tunnels")
	makeOpenDir(t, d)

	err := secureTunnelSocketDir(d, uint32(os.Geteuid())+1)

	require.Error(t, err)
	fi, statErr := os.Stat(d)
	require.NoError(t, statErr)
	assert.Equal(t, os.FileMode(0777), fi.Mode().Perm())
}
