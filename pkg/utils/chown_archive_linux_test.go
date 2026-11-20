package utils

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func openChownArchiveTestRoot(t *testing.T, root string) int {
	t.Helper()
	fd, err := unix.Open(root, openDirFlags, 0)
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, unix.Close(fd)) })
	probe, err := openChownChild(fd, ".", openDirFlags, true)
	if err == unix.ENOSYS || err == unix.EPERM {
		t.Skipf("openat2 unavailable: %v", err)
	}
	require.NoError(t, err)
	require.NoError(t, unix.Close(probe))
	return fd
}

func TestChownArchiveSkipsSymlink(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	link := filepath.Join(root, "link")
	require.NoError(t, os.Symlink(outside, link))
	oldHook := beforeOpen
	t.Cleanup(func() { beforeOpen = oldHook })
	beforeOpen = func(child string) { assert.NotEqual(t, link, child) }

	fd := openChownArchiveTestRoot(t, root)
	skipped, err := ChownArchive(context.Background(), fd, root, -1, -1, -1)
	require.NoError(t, err)
	assert.Zero(t, skipped)
	target, err := os.Readlink(link)
	require.NoError(t, err)
	assert.Equal(t, outside, target)
}

func TestChownArchiveCancellation(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.Mkdir(filepath.Join(root, "child"), 0700))
	fd := openChownArchiveTestRoot(t, root)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	oldReadDir, oldOpen := afterReadDir, beforeOpen
	t.Cleanup(func() { afterReadDir, beforeOpen = oldReadDir, oldOpen })
	afterReadDir = func(string) { cancel() }
	beforeOpen = func(child string) { assert.Fail(t, "opened child after cancellation", "%s", child) }

	_, err := ChownArchive(ctx, fd, root, -1, -1, -1)
	assert.ErrorIs(t, err, context.Canceled)
}

func TestChownArchiveRefusesBindMount(t *testing.T) {
	const rootEnv = "ALPAMON_TEST_CHOWN_ARCHIVE_ROOT"
	if root := os.Getenv(rootEnv); root != "" {
		fd := openChownArchiveTestRoot(t, root)
		_, err := openArchiveEntryFallback(fd, "mounted", openDirFlags)
		assert.ErrorIs(t, err, unix.EXDEV)
		_, err = ChownArchive(context.Background(), fd, root, -1, -1, -1)
		assert.ErrorIs(t, err, unix.EXDEV)
		return
	}

	unshare, err := exec.LookPath("unshare")
	if err != nil {
		t.Skip("unshare unavailable")
	}
	root, outside := t.TempDir(), t.TempDir()
	mountpoint := filepath.Join(root, "mounted")
	require.NoError(t, os.Mkdir(mountpoint, 0700))
	exe, err := os.Executable()
	require.NoError(t, err)
	cmd := exec.Command(unshare, "--user", "--map-root-user", "--mount", "--", "sh", "-c",
		`mount --bind "$1" "$2" || exit 1
printf 'bind mounted\n'
exec "$3" -test.run '^TestChownArchiveRefusesBindMount$' -test.v`,
		"sh", outside, mountpoint, exe)
	cmd.Env = append(os.Environ(), rootEnv+"="+root)
	output, err := cmd.CombinedOutput()
	if !strings.Contains(string(output), "bind mounted\n") {
		t.Skipf("unprivileged bind mount unavailable: %s (%v)", output, err)
	}
	require.NoError(t, err, "%s", output)
	if strings.Contains(string(output), "--- SKIP:") {
		t.Skipf("mount test skipped in namespace: %s", output)
	}
}

func TestOpenArchiveEntryFallback(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.Mkdir(filepath.Join(root, "child"), 0700))
	require.NoError(t, os.Symlink("child", filepath.Join(root, "link")))
	require.NoError(t, os.WriteFile(filepath.Join(root, "file"), nil, 0600))
	fd := openChownArchiveTestRoot(t, root)

	for _, tc := range []struct {
		name  string
		flags int
	}{
		{"child", openDirFlags},
		{"file", openFileFlags},
		{"link", unix.O_PATH | unix.O_NOFOLLOW | unix.O_CLOEXEC},
	} {
		child, err := openArchiveEntryFallback(fd, tc.name, tc.flags)
		require.NoError(t, err)
		assert.NoError(t, unix.Close(child))
	}
	_, err := openArchiveEntryFallback(fd, "link", openFileFlags)
	assert.ErrorIs(t, err, unix.ELOOP)

	proc, err := unix.Open("/", openDirFlags, 0)
	require.NoError(t, err)
	defer func() { assert.NoError(t, unix.Close(proc)) }()
	_, err = openArchiveEntryFallback(proc, "proc", openDirFlags)
	assert.ErrorIs(t, err, unix.EXDEV)
}
