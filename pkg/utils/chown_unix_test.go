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

const (
	_victimID   = 65534
	_newOwnerID = 4242
)

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

// newOwnerFor returns an owner that path does not have yet, so a passing chown
// test proves the entry was changed: another uid as root, else another of our groups.
func newOwnerFor(t *testing.T, path string) (uid, gid int) {
	t.Helper()
	if os.Geteuid() == 0 {
		return _newOwnerID, _newOwnerID
	}
	_, curGID := ownerOf(t, path)
	groups, err := os.Getgroups()
	require.NoError(t, err)
	for _, g := range groups {
		if g != curGID {
			return os.Getuid(), g
		}
	}
	t.Skip("needs root or a second group to change an owner")
	return 0, 0
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
	dirs := []string{root, filepath.Join(root, "a"), filepath.Join(root, "a", "b")}
	uid, gid := newOwnerFor(t, root)

	err := ChownRecursive(root, uid, gid)

	require.NoError(t, err)
	for _, p := range append(files, dirs...) {
		requireOwner(t, p, uid, gid)
	}
}

func TestChownRecursive_ChownsAFileRoot(t *testing.T) {
	f := filepath.Join(t.TempDir(), "f")
	require.NoError(t, os.WriteFile(f, []byte("x"), 0o644))
	uid, gid := newOwnerFor(t, f)

	err := ChownRecursive(f, uid, gid)

	require.NoError(t, err)
	requireOwner(t, f, uid, gid)
}

func TestChownRecursive_LeavesASymlinkRootAlone(t *testing.T) {
	requireRoot(t)
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	require.NoError(t, os.Mkdir(target, 0o755))
	require.NoError(t, os.Chown(target, _victimID, _victimID))
	link := filepath.Join(dir, "link")
	require.NoError(t, os.Symlink(target, link))

	err := ChownRecursive(link, _newOwnerID, _newOwnerID)

	require.NoError(t, err)
	requireOwner(t, target, _victimID, _victimID)
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
	require.NoError(t, os.Chown(victim, _victimID, _victimID))
	tree := filepath.Join(t.TempDir(), "tree")
	require.NoError(t, os.Mkdir(tree, 0o755))
	own := filepath.Join(tree, "own")
	require.NoError(t, os.WriteFile(own, []byte("x"), 0o644))
	require.NoError(t, os.Symlink(victim, filepath.Join(tree, "link")))

	err := ChownRecursive(tree, _newOwnerID, _newOwnerID)

	require.NoError(t, err)
	requireOwner(t, victim, _victimID, _victimID)
	requireOwner(t, own, _newOwnerID, _newOwnerID)
	requireOwner(t, tree, _newOwnerID, _newOwnerID)
	requireOwner(t, filepath.Join(tree, "link"), 0, 0)
}

func TestChownRecursive_DoesNotDescendIntoADirectorySymlink(t *testing.T) {
	requireRoot(t)
	outside := t.TempDir()
	victimDir := filepath.Join(outside, "ssh")
	require.NoError(t, os.Mkdir(victimDir, 0o700))
	victimFile := filepath.Join(victimDir, "authorized_keys")
	require.NoError(t, os.WriteFile(victimFile, []byte("x"), 0o600))
	require.NoError(t, os.Chown(victimDir, _victimID, _victimID))
	require.NoError(t, os.Chown(victimFile, _victimID, _victimID))
	tree := filepath.Join(t.TempDir(), "tree")
	require.NoError(t, os.Mkdir(tree, 0o755))
	require.NoError(t, os.Symlink(victimDir, filepath.Join(tree, "dirlink")))

	err := ChownRecursive(tree, _newOwnerID, _newOwnerID)

	require.NoError(t, err)
	requireOwner(t, victimDir, _victimID, _victimID)
	requireOwner(t, victimFile, _victimID, _victimID)
	requireOwner(t, tree, _newOwnerID, _newOwnerID)
}

func TestChownRecursive_ChownsATreeDeeperThanTheFdLimit(t *testing.T) {
	root := t.TempDir()
	leafDir := root
	for range 200 {
		leafDir = filepath.Join(leafDir, "d")
	}
	require.NoError(t, os.MkdirAll(leafDir, 0o755))
	leaf := filepath.Join(leafDir, "leaf.txt")
	require.NoError(t, os.WriteFile(leaf, []byte("x"), 0o644))
	uid, gid := newOwnerFor(t, root)
	var prev syscall.Rlimit
	require.NoError(t, syscall.Getrlimit(syscall.RLIMIT_NOFILE, &prev))
	lowered := prev
	lowered.Cur = 64
	require.NoError(t, syscall.Setrlimit(syscall.RLIMIT_NOFILE, &lowered))
	t.Cleanup(func() { _ = syscall.Setrlimit(syscall.RLIMIT_NOFILE, &prev) })

	err := ChownRecursive(root, uid, gid)

	require.NoError(t, err)
	requireOwner(t, leafDir, uid, gid)
	requireOwner(t, leaf, uid, gid)
}
