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

const newOwnerID = 4242

func ownerOf(t *testing.T, path string) (uid, gid int) {
	t.Helper()
	info, err := os.Lstat(path)
	require.NoError(t, err)
	st, ok := info.Sys().(*syscall.Stat_t)
	require.True(t, ok)
	return int(st.Uid), int(st.Gid)
}

func assertOwner(t *testing.T, path string, uid, gid int) {
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
		return newOwnerID, newOwnerID
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

// afterListing runs fn once the walk has listed dir.
func afterListing(t *testing.T, dir string, fn func()) {
	t.Helper()
	prev := afterReadDir
	t.Cleanup(func() { afterReadDir = prev })
	afterReadDir = func(listed string) {
		if listed == dir {
			fn()
		}
	}
}

// beforeOpening runs fn once the walk has stat'ed child as a directory, before it opens it.
func beforeOpening(t *testing.T, child string, fn func()) {
	t.Helper()
	prev := beforeOpenDir
	t.Cleanup(func() { beforeOpenDir = prev })
	beforeOpenDir = func(opened string) {
		if opened == child {
			fn()
		}
	}
}

// treeWithVictim makes root/sub/file.txt and outside/victim beside the tree.
func treeWithVictim(t *testing.T) (root, sub, outside, victim string) {
	t.Helper()
	root, outside = t.TempDir(), t.TempDir()
	sub = filepath.Join(root, "sub")
	require.NoError(t, os.Mkdir(sub, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(sub, "file.txt"), []byte("x"), 0o644))
	victim = filepath.Join(outside, "victim")
	require.NoError(t, os.WriteFile(victim, []byte("x"), 0o644))
	return root, sub, outside, victim
}

// assertUnchanged checks that ChownRecursive left path with the owner it had when this was called.
func assertUnchanged(t *testing.T, path string) func() {
	t.Helper()
	uid, gid := ownerOf(t, path)
	return func() { assertOwner(t, path, uid, gid) }
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
		assertOwner(t, p, uid, gid)
	}
}

func TestChownRecursive_ChownsAFileRoot(t *testing.T) {
	f := filepath.Join(t.TempDir(), "f")
	require.NoError(t, os.WriteFile(f, []byte("x"), 0o644))
	uid, gid := newOwnerFor(t, f)

	err := ChownRecursive(f, uid, gid)

	require.NoError(t, err)
	assertOwner(t, f, uid, gid)
}

func TestChownRecursive_LeavesASymlinkRootAlone(t *testing.T) {
	_, _, outside, victim := treeWithVictim(t)
	for name, target := range map[string]string{
		"to a directory": outside,
		"to a file":      victim,
		"dangling":       filepath.Join(outside, "missing"),
	} {
		t.Run(name, func(t *testing.T) {
			link := filepath.Join(t.TempDir(), "link")
			require.NoError(t, os.Symlink(target, link))
			uid, gid := newOwnerFor(t, link)
			outsideKept, victimKept, linkKept := assertUnchanged(t, outside), assertUnchanged(t, victim), assertUnchanged(t, link)

			err := ChownRecursive(link, uid, gid)

			require.NoError(t, err)
			outsideKept()
			victimKept()
			linkKept()
		})
	}
}

func TestChownRecursive_RejectsEmptyPath(t *testing.T) {
	err := ChownRecursive("", 0, 0)

	assert.EqualError(t, err, "path must not be empty")
}

func TestChownRecursive_FailsOnAMissingPath(t *testing.T) {
	err := ChownRecursive(filepath.Join(t.TempDir(), "missing"), 0, 0)

	assert.ErrorIs(t, err, os.ErrNotExist)
}

func TestChownRecursive_FailsWhenAParentIsAFile(t *testing.T) {
	file := filepath.Join(t.TempDir(), "file")
	require.NoError(t, os.WriteFile(file, []byte("x"), 0o644))

	err := ChownRecursive(filepath.Join(file, "child"), os.Getuid(), os.Getgid())

	assert.ErrorIs(t, err, syscall.ENOTDIR)
}

func TestChownRecursive_ChownsAFifoRootWithoutBlocking(t *testing.T) {
	fifo := filepath.Join(t.TempDir(), "fifo")
	require.NoError(t, syscall.Mkfifo(fifo, 0o644))
	uid, gid := newOwnerFor(t, fifo)

	err := ChownRecursive(fifo, uid, gid)

	require.NoError(t, err)
	assertOwner(t, fifo, uid, gid)
}

func TestChownRecursive_DoesNotFollowAFileSymlinkOutOfTheTree(t *testing.T) {
	root, sub, _, victim := treeWithVictim(t)
	link := filepath.Join(root, "link")
	require.NoError(t, os.Symlink(victim, link))
	uid, gid := newOwnerFor(t, root)
	victimKept, linkKept := assertUnchanged(t, victim), assertUnchanged(t, link)

	err := ChownRecursive(root, uid, gid)

	require.NoError(t, err)
	victimKept()
	linkKept()
	assertOwner(t, filepath.Join(sub, "file.txt"), uid, gid)
}

func TestChownRecursive_DoesNotDescendIntoADirectorySymlink(t *testing.T) {
	root, _, outside, victim := treeWithVictim(t)
	require.NoError(t, os.Symlink(outside, filepath.Join(root, "dirlink")))
	uid, gid := newOwnerFor(t, root)
	outsideKept, victimKept := assertUnchanged(t, outside), assertUnchanged(t, victim)

	err := ChownRecursive(root, uid, gid)

	require.NoError(t, err)
	outsideKept()
	victimKept()
	assertOwner(t, root, uid, gid)
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
	assertOwner(t, leafDir, uid, gid)
	assertOwner(t, leaf, uid, gid)
}

func TestChownRecursive_SkipsEntriesRemovedDuringTheWalk(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.Mkdir(filepath.Join(root, "gone-dir"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, "gone.txt"), []byte("x"), 0o644))
	kept := filepath.Join(root, "kept.txt")
	require.NoError(t, os.WriteFile(kept, []byte("x"), 0o644))
	uid, gid := newOwnerFor(t, root)
	afterListing(t, root, func() {
		require.NoError(t, os.Remove(filepath.Join(root, "gone-dir")))
		require.NoError(t, os.Remove(filepath.Join(root, "gone.txt")))
	})

	err := ChownRecursive(root, uid, gid)

	require.NoError(t, err)
	assertOwner(t, root, uid, gid)
	assertOwner(t, kept, uid, gid)
}

func TestChownRecursive_DoesNotFollowADirectorySwappedForASymlinkAfterListing(t *testing.T) {
	root, sub, outside, victim := treeWithVictim(t)
	uid, gid := newOwnerFor(t, root)
	victimKept := assertUnchanged(t, victim)
	afterListing(t, root, func() {
		require.NoError(t, os.RemoveAll(sub))
		require.NoError(t, os.Symlink(outside, sub))
	})

	err := ChownRecursive(root, uid, gid)

	require.NoError(t, err)
	victimKept()
	assertOwner(t, root, uid, gid)
}

func TestChownRecursive_FailsClosedWhenADirectoryBecomesASymlinkBeforeItIsOpened(t *testing.T) {
	root, sub, outside, victim := treeWithVictim(t)
	uid, gid := newOwnerFor(t, root)
	victimKept := assertUnchanged(t, victim)
	beforeOpening(t, sub, func() {
		require.NoError(t, os.RemoveAll(sub))
		require.NoError(t, os.Symlink(outside, sub))
	})

	err := ChownRecursive(root, uid, gid)

	assert.ErrorContains(t, err, "open "+sub)
	victimKept()
}

func TestChownRecursive_FailsClosedWhenADirectoryBecomesAFileBeforeItIsOpened(t *testing.T) {
	root, sub, _, _ := treeWithVictim(t)
	uid, gid := newOwnerFor(t, root)
	beforeOpening(t, sub, func() {
		require.NoError(t, os.RemoveAll(sub))
		require.NoError(t, os.WriteFile(sub, []byte("x"), 0o644))
	})

	err := ChownRecursive(root, uid, gid)

	assert.ErrorIs(t, err, syscall.ENOTDIR)
	assert.ErrorContains(t, err, "open "+sub)
}

func TestChownRecursive_FailsClosedWhenADirectoryMovesOutOfTheTree(t *testing.T) {
	root, sub, outside, _ := treeWithVictim(t)
	uid, gid := newOwnerFor(t, root)
	afterListing(t, sub, func() {
		require.NoError(t, os.Rename(sub, filepath.Join(outside, "sub")))
	})

	err := ChownRecursive(root, uid, gid)

	assert.EqualError(t, err, root+" changed while walking")
}

func TestChownRecursive_ClimbsBackWhenTheCurrentDirectoryIsRemoved(t *testing.T) {
	root := t.TempDir()
	gone := filepath.Join(root, "gone")
	require.NoError(t, os.Mkdir(gone, 0o755))
	kept := filepath.Join(root, "kept.txt")
	require.NoError(t, os.WriteFile(kept, []byte("x"), 0o644))
	uid, gid := newOwnerFor(t, root)
	afterListing(t, gone, func() {
		require.NoError(t, os.Remove(gone))
	})

	err := ChownRecursive(root, uid, gid)

	require.NoError(t, err)
	assertOwner(t, root, uid, gid)
	assertOwner(t, kept, uid, gid)
}
