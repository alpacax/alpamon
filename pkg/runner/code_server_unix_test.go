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

func TestCodeServerSysProcAttr_CarriesTheResolvedCredential(t *testing.T) {
	cred := &syscall.Credential{Uid: 501, Gid: 20}
	shared := &syscall.SysProcAttr{Credential: cred}

	attr := codeServerSysProcAttr(shared)

	assert.Same(t, cred, attr.Credential)
	assert.True(t, attr.Setpgid)
	assert.NotSame(t, shared, attr)
	assert.False(t, shared.Setpgid, "the manager's shared SysProcAttr must stay untouched")
}

func TestCodeServerSysProcAttr_NilKeepsTheCurrentUser(t *testing.T) {
	attr := codeServerSysProcAttr(nil)

	assert.Nil(t, attr.Credential)
	assert.True(t, attr.Setpgid)
}

// makeOpenTree builds a tree whose modes let group and other write, like the macOS release tarball.
func makeOpenTree(t *testing.T) (root, dir, file, link string) {
	t.Helper()
	root = filepath.Join(t.TempDir(), "code-server")
	dir = filepath.Join(root, "bin")
	file = filepath.Join(dir, "code-server")
	link = filepath.Join(root, "current")
	require.NoError(t, os.MkdirAll(dir, 0755))
	require.NoError(t, os.WriteFile(file, nil, 0644))
	require.NoError(t, os.Symlink(file, link))
	require.NoError(t, os.Chmod(file, 0777))
	require.NoError(t, os.Chmod(dir, 0777))
	require.NoError(t, os.Chmod(root, 0775))
	return root, dir, file, link
}

func TestSecureCodeServerTree_DropsGroupAndOtherWrite(t *testing.T) {
	root, dir, file, link := makeOpenTree(t)

	err := secureCodeServerTree(root, os.Getuid(), os.Getgid())

	require.NoError(t, err)
	for path, want := range map[string]os.FileMode{root: 0755, dir: 0755, file: 0755} {
		fi, err := os.Stat(path)
		require.NoError(t, err)
		assert.Equal(t, want, fi.Mode().Perm(), path)
	}
	fi, err := os.Lstat(link)
	require.NoError(t, err)
	assert.Equal(t, os.ModeSymlink, fi.Mode().Type())
}

func TestSecureCodeServerTree_GivesTheTreeToRootWhenRoot(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("chown to another uid needs root")
	}
	root, dir, file, link := makeOpenTree(t)
	for _, p := range []string{root, dir, file, link} {
		require.NoError(t, os.Lchown(p, 501, 20)) // the owner macOS tar restores from the archive
	}

	err := secureCodeServerTree(root, 0, 0)

	require.NoError(t, err)
	for _, p := range []string{root, dir, file, link} {
		assert.Equal(t, [2]uint32{0, 0}, lstatOwner(t, p), p)
	}
}

func lstatOwner(t *testing.T, path string) [2]uint32 {
	t.Helper()
	fi, err := os.Lstat(path)
	require.NoError(t, err)
	st, ok := fi.Sys().(*syscall.Stat_t)
	require.True(t, ok)
	return [2]uint32{st.Uid, st.Gid}
}

func ownersOfTempDirs() []uint32 {
	return []uint32{0, uint32(os.Geteuid())} // the temp dir chain mixes root and the test user
}

func TestVerifyOwnedPath_AcceptsATreeOnlyTheOwnersCanChange(t *testing.T) {
	root, _, file, _ := makeOpenTree(t)
	require.NoError(t, secureCodeServerTree(root, os.Getuid(), os.Getgid()))

	err := verifyOwnedPath(file, ownersOfTempDirs()...)

	assert.NoError(t, err)
}

func TestVerifyOwnedPath_RefusesAGroupWritableParent(t *testing.T) {
	root, dir, file, _ := makeOpenTree(t)
	require.NoError(t, secureCodeServerTree(root, os.Getuid(), os.Getgid()))
	require.NoError(t, os.Chmod(dir, 0775))

	err := verifyOwnedPath(file, ownersOfTempDirs()...)

	assert.ErrorContains(t, err, "writable by group or other")
}

func TestVerifyOwnedPath_RefusesAFileOwnedByAnotherAccount(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root owns the temp files, so they are not foreign")
	}
	root, _, file, _ := makeOpenTree(t)
	require.NoError(t, secureCodeServerTree(root, os.Getuid(), os.Getgid()))

	err := verifyOwnedPath(file, 0)

	assert.ErrorContains(t, err, "which is not allowed")
}

func TestVerifyOwnedPath_ChecksTheSymlinkTarget(t *testing.T) {
	root, dir, _, link := makeOpenTree(t)
	require.NoError(t, secureCodeServerTree(root, os.Getuid(), os.Getgid()))
	require.NoError(t, os.Chmod(dir, 0777)) // the link's own dir stays safe; its target's does not

	err := verifyOwnedPath(link, ownersOfTempDirs()...)

	assert.ErrorContains(t, err, "writable by group or other")
}
