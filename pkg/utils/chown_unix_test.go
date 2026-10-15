//go:build !windows

package utils

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const victimID = 65534

func ownerOf(t *testing.T, path string) (uid, gid int) {
	t.Helper()
	info, err := os.Lstat(path)
	require.NoError(t, err)
	st, ok := info.Sys().(*syscall.Stat_t)
	require.True(t, ok)
	return int(st.Uid), int(st.Gid)
}

func requireOwner(t *testing.T, path string, uid, gid int) {
	t.Helper()
	gotUID, gotGID := ownerOf(t, path)
	assert.Equal(t, uid, gotUID, path)
	assert.Equal(t, gid, gotGID, path)
}

func requireRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root to chown to another owner")
	}
}

func TestChownRecursive_ChownsEveryEntryInTheTree(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(root, "a", "b"), 0o755))
	files := []string{
		filepath.Join(root, "top.txt"),
		filepath.Join(root, "a", "mid.txt"),
		filepath.Join(root, "a", "b", "leaf.txt"),
	}
	for _, f := range files {
		require.NoError(t, os.WriteFile(f, []byte("x"), 0o644))
	}
	uid, gid := os.Getuid(), os.Getgid()

	err := ChownRecursive(root, uid, gid)

	require.NoError(t, err)
	for _, p := range append(files, root, filepath.Join(root, "a"), filepath.Join(root, "a", "b")) {
		requireOwner(t, p, uid, gid)
	}
}

func TestChownRecursive_ChownsAFileRoot(t *testing.T) {
	f := filepath.Join(t.TempDir(), "f")
	require.NoError(t, os.WriteFile(f, []byte("x"), 0o644))

	err := ChownRecursive(f, os.Getuid(), os.Getgid())

	require.NoError(t, err)
	requireOwner(t, f, os.Getuid(), os.Getgid())
}

func TestChownRecursive_LeavesASymlinkRootAlone(t *testing.T) {
	requireRoot(t)
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	require.NoError(t, os.Mkdir(target, 0o755))
	require.NoError(t, os.Chown(target, victimID, victimID))
	link := filepath.Join(dir, "link")
	require.NoError(t, os.Symlink(target, link))

	err := ChownRecursive(link, 0, 0)

	require.NoError(t, err)
	requireOwner(t, target, victimID, victimID)
	requireOwner(t, link, 0, 0)
}

func TestChownRecursive_LeavesASymlinkRootAloneForAnyUser(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	require.NoError(t, os.WriteFile(target, []byte("x"), 0o644))
	link := filepath.Join(dir, "link")
	require.NoError(t, os.Symlink(target, link))
	dangling := filepath.Join(dir, "dangling")
	require.NoError(t, os.Symlink(filepath.Join(dir, "missing"), dangling))

	require.NoError(t, ChownRecursive(link, os.Getuid(), os.Getgid()))
	require.NoError(t, ChownRecursive(dangling, os.Getuid(), os.Getgid()))
}

func TestChownRecursive_RejectsEmptyPath(t *testing.T) {
	err := ChownRecursive("", 0, 0)

	assert.EqualError(t, err, "path must not be empty")
}

func TestChownRecursive_FailsOnAMissingPath(t *testing.T) {
	err := ChownRecursive(filepath.Join(t.TempDir(), "missing"), 0, 0)

	require.Error(t, err)
	assert.ErrorIs(t, err, os.ErrNotExist)
}

func TestChownRecursive_DoesNotFollowAFileSymlinkOutOfTheTree(t *testing.T) {
	requireRoot(t)
	outside := t.TempDir()
	victim := filepath.Join(outside, "victim")
	require.NoError(t, os.WriteFile(victim, []byte("x"), 0o644))
	require.NoError(t, os.Chown(victim, victimID, victimID))
	tree := filepath.Join(t.TempDir(), "tree")
	require.NoError(t, os.Mkdir(tree, 0o755))
	own := filepath.Join(tree, "own")
	require.NoError(t, os.WriteFile(own, []byte("x"), 0o644))
	require.NoError(t, os.Symlink(victim, filepath.Join(tree, "link")))

	err := ChownRecursive(tree, 0, 0)

	require.NoError(t, err)
	requireOwner(t, victim, victimID, victimID)
	requireOwner(t, own, 0, 0)
	requireOwner(t, tree, 0, 0)
	requireOwner(t, filepath.Join(tree, "link"), 0, 0)
}

func TestChownRecursive_DoesNotDescendIntoADirectorySymlink(t *testing.T) {
	requireRoot(t)
	outside := t.TempDir()
	victimDir := filepath.Join(outside, "ssh")
	require.NoError(t, os.Mkdir(victimDir, 0o700))
	victimFile := filepath.Join(victimDir, "authorized_keys")
	require.NoError(t, os.WriteFile(victimFile, []byte("x"), 0o600))
	require.NoError(t, os.Chown(victimDir, victimID, victimID))
	require.NoError(t, os.Chown(victimFile, victimID, victimID))
	tree := filepath.Join(t.TempDir(), "tree")
	require.NoError(t, os.Mkdir(tree, 0o755))
	require.NoError(t, os.Symlink(victimDir, filepath.Join(tree, "dirlink")))

	err := ChownRecursive(tree, 0, 0)

	require.NoError(t, err)
	requireOwner(t, victimDir, victimID, victimID)
	requireOwner(t, victimFile, victimID, victimID)
	requireOwner(t, tree, 0, 0)
}
