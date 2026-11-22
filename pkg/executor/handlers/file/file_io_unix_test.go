//go:build !windows

package file

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"testing/iotest"

	"github.com/alpacax/alpamon/v2/pkg/executor/handlers/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWriteFileAs_TeePath_CreatesParentDir(t *testing.T) {
	for _, dir := range []string{"nested/deep", "space and 'quote'/$literal;name"} {
		t.Run(strings.ReplaceAll(dir, "/", "_"), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), dir, "out 'file'.bin")
			// Select the subprocess branch without changing credentials or requiring root.
			err := writeFileAs(t.Context(), path, strings.NewReader("payload"), &syscall.SysProcAttr{}, true)
			require.NoError(t, err)
			assert.DirExists(t, filepath.Dir(path))
			got, err := os.ReadFile(path)
			require.NoError(t, err)
			assert.Equal(t, "payload", string(got))

			err = writeFileAs(t.Context(), path, strings.NewReader("next"), &syscall.SysProcAttr{}, true)
			require.NoError(t, err)
			got, err = os.ReadFile(path)
			require.NoError(t, err)
			assert.Equal(t, "next", string(got))
		})
	}
}

func TestWriteFileAs_RejectsNonAbsolutePath(t *testing.T) {
	err := writeFileAs(t.Context(), "relative/x", strings.NewReader("payload"), nil, true)
	require.Error(t, err)
	assert.ErrorContains(t, err, "absolute")
}

func TestWriteFileAs_TeePath_RejectsUnwritableParent(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can write through directory mode restrictions")
	}
	dir := t.TempDir()
	require.NoError(t, os.Chmod(dir, 0555))
	t.Cleanup(func() { require.NoError(t, os.Chmod(dir, 0700)) })
	path := filepath.Join(dir, "missing", "out.bin")

	err := writeFileAs(t.Context(), path, strings.NewReader("payload"), &syscall.SysProcAttr{}, true)
	require.Error(t, err)
	_, err = os.Stat(filepath.Dir(path))
	assert.ErrorIs(t, err, os.ErrNotExist)
}

func TestWriteFileAs_TeePath_SurfacesTeeFailureAfterMkdirSucceeds(t *testing.T) {
	dir := t.TempDir()
	// mkdir -p is a no-op here since the parent already exists, so this exercises
	// "mkdir succeeds, tee fails" rather than the mkdir-failure branch above.
	path := filepath.Join(dir, "target")
	require.NoError(t, os.Mkdir(path, 0755))

	err := writeFileAs(t.Context(), path, strings.NewReader("payload"), &syscall.SysProcAttr{}, true)
	require.Error(t, err)
	// tee's "Is a directory" message is locale-dependent; the path it names is not.
	assert.ErrorContains(t, err, path)
	assert.DirExists(t, path)
}

func TestWriteFileAs_TeePath_KeepsUnwritableTargetOnTeeFailure(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can write through file mode restrictions")
	}
	path := filepath.Join(t.TempDir(), "precious.conf")
	require.NoError(t, os.WriteFile(path, []byte("ORIGINAL"), 0444))

	err := writeFileAs(t.Context(), path, strings.NewReader("payload"), &syscall.SysProcAttr{}, true)
	require.Error(t, err)
	got, readErr := os.ReadFile(path)
	require.NoError(t, readErr)
	assert.Equal(t, "ORIGINAL", string(got))
}

func TestWriteFileAs_TeePath_KeepsUnwritableTargetOnSourceReadFailure(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can write through file mode restrictions")
	}
	path := filepath.Join(t.TempDir(), "precious.conf")
	require.NoError(t, os.WriteFile(path, []byte("ORIGINAL"), 0444))

	err := writeFileAs(t.Context(), path, iotest.ErrReader(errors.New("connection reset")), &syscall.SysProcAttr{}, true)
	require.Error(t, err)
	got, readErr := os.ReadFile(path)
	require.NoError(t, readErr)
	assert.Equal(t, "ORIGINAL", string(got))
}

func TestWriteFileAs_TeePath_LeavesTruncatedPreexistingTargetOnSourceReadFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "out.bin")
	require.NoError(t, os.WriteFile(path, []byte("ORIGINAL"), 0644))

	err := writeFileAs(t.Context(), path, iotest.ErrReader(errors.New("boom")), &syscall.SysProcAttr{}, true)
	require.Error(t, err)
	// tee opened and truncated it before the read failed, so the old content is gone either
	// way; what matters is that createdTarget stays false and the file itself is not unlinked.
	got, readErr := os.ReadFile(path)
	require.NoError(t, readErr)
	assert.Empty(t, string(got))
}

func TestWriteFileAs_TeePath_RemovesFreshTargetOnSourceReadFailure(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.bin")

	err := writeFileAs(t.Context(), path, iotest.ErrReader(errors.New("boom")), &syscall.SysProcAttr{}, true)
	require.Error(t, err)
	assert.ErrorContains(t, err, "boom")
	_, statErr := os.Stat(path)
	assert.ErrorIs(t, statErr, os.ErrNotExist)
}

func TestFirstMissingAncestor(t *testing.T) {
	dir := t.TempDir()
	existing := filepath.Join(dir, "existing")
	require.NoError(t, os.Mkdir(existing, 0755))

	danglingParent := filepath.Join(dir, "dangling")
	require.NoError(t, os.Symlink(filepath.Join(dir, "nonexistent-target"), danglingParent))

	nonDirParent := filepath.Join(dir, "not-a-dir")
	require.NoError(t, os.WriteFile(nonDirParent, []byte("x"), 0644))

	tests := []struct {
		name string
		dir  string
		want string
	}{
		{"existing directory", existing, ""},
		{"missing chain", filepath.Join(dir, "a", "b", "c"), filepath.Join(dir, "a")},
		{"dangling symlink parent", filepath.Join(danglingParent, "child"), filepath.Join(danglingParent, "child")},
		// Lstat through a non-directory component fails with ENOTDIR, not ENOENT--the same
		// "state is unknown" branch a permission-denied stat takes, so this reports "" too.
		{"non-directory parent", filepath.Join(nonDirParent, "child"), ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, firstMissingAncestor(tt.dir))
		})
	}

	t.Run("stat error", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("root bypasses permission checks")
		}
		blocked := filepath.Join(dir, "blocked")
		require.NoError(t, os.Mkdir(blocked, 0000))
		t.Cleanup(func() { require.NoError(t, os.Chmod(blocked, 0700)) })
		assert.Equal(t, "", firstMissingAncestor(filepath.Join(blocked, "child")))
	})
}

func TestWriteFileAs_TeePath_RemovesDirsItCreatedOnFailure(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "new", "nested", "out.bin")

	err := writeFileAs(t.Context(), path, iotest.ErrReader(errors.New("boom")), &syscall.SysProcAttr{}, true)
	require.Error(t, err)
	assert.ErrorContains(t, err, "boom")
	_, statErr := os.Stat(filepath.Join(dir, "new"))
	assert.ErrorIs(t, statErr, os.ErrNotExist)
}

func TestWriteFileAs_TeePath_KeepsPreexistingParentOnFailure(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "sub")
	require.NoError(t, os.Mkdir(sub, 0755))
	path := filepath.Join(sub, "out.bin")

	err := writeFileAs(t.Context(), path, iotest.ErrReader(errors.New("boom")), &syscall.SysProcAttr{}, true)
	require.Error(t, err)
	assert.ErrorContains(t, err, "boom")
	assert.DirExists(t, sub)
}

func TestRootOnly_WriteFileAsCreatesParentsAsUser(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("credential demotion requires root")
	}
	// Only the demoted user should own the newly created parents.
	uid, gid := nobodyIDs(t)
	dir := t.TempDir()
	parent := filepath.Dir(dir)
	parentInfo, err := os.Stat(parent)
	require.NoError(t, err)
	require.NoError(t, os.Chmod(parent, 0755))
	t.Cleanup(func() { require.NoError(t, os.Chmod(parent, parentInfo.Mode().Perm())) })
	require.NoError(t, os.Chown(dir, uid, gid))
	attr := &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid)}}
	for _, overwrite := range []bool{true, false} {
		path := filepath.Join(dir, strconv.FormatBool(overwrite), "nested", "deep", "out.bin")
		require.NoError(t, writeFileAs(t.Context(), path, strings.NewReader("payload"), attr, overwrite))
		for _, created := range []string{filepath.Dir(filepath.Dir(path)), filepath.Dir(path), path} {
			st, err := os.Stat(created)
			require.NoError(t, err)
			stat, ok := st.Sys().(*syscall.Stat_t)
			require.True(t, ok)
			assert.EqualValues(t, uid, stat.Uid)
			assert.EqualValues(t, gid, stat.Gid)
		}
		got, err := os.ReadFile(path)
		require.NoError(t, err)
		assert.Equal(t, "payload", string(got))
	}
}

func TestRootOnly_WriteFileAsCleanupCannotRemoveRootOwnedDirectory(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("credential demotion requires root")
	}
	uid, gid := nobodyIDs(t)
	dir := t.TempDir()
	parent := filepath.Dir(dir)
	parentInfo, err := os.Stat(parent)
	require.NoError(t, err)
	require.NoError(t, os.Chmod(parent, 0755))
	t.Cleanup(func() { require.NoError(t, os.Chmod(parent, parentInfo.Mode().Perm())) })
	require.NoError(t, os.Chmod(dir, 0755))
	userParent := filepath.Join(dir, "requester")
	otherParent := filepath.Join(dir, "unrelated")
	require.NoError(t, os.Mkdir(userParent, 0755))
	require.NoError(t, os.Chown(userParent, uid, gid))
	require.NoError(t, os.Mkdir(otherParent, 0755))
	unrelated := filepath.Join(otherParent, "new")
	require.NoError(t, os.Mkdir(unrelated, 0755))
	cleanupRan := false
	original := fileHelperCommand
	t.Cleanup(func() { fileHelperCommand = original })
	fileHelperCommand = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		if name == "/bin/rmdir" {
			cleanupRan = true
		}
		return original(ctx, name, args...)
	}
	source := &cleanupErrorReader{swap: func() error {
		if err := os.Rename(userParent, userParent+"-old"); err != nil {
			return err
		}
		return os.Symlink(otherParent, userParent)
	}}
	attr := &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid)}}
	err = writeFileAs(t.Context(), filepath.Join(userParent, "new", "output"), source, attr, true)
	require.Error(t, err)
	require.NoError(t, source.err)
	require.Nil(t, source.swap, "ancestor swap must run")
	assert.True(t, cleanupRan, "cleanup walk must run")
	target, linkErr := os.Readlink(userParent)
	require.NoError(t, linkErr)
	assert.Equal(t, otherParent, target)
	assert.DirExists(t, unrelated, "cleanup runs with the requester's credentials")
	entries, err := os.ReadDir(unrelated)
	require.NoError(t, err)
	assert.Empty(t, entries)
}

func nobodyIDs(t *testing.T) (int, int) {
	t.Helper()
	usr, err := user.Lookup("nobody")
	if err != nil {
		t.Skipf("no nobody account: %v", err)
	}
	uid, err := strconv.ParseUint(usr.Uid, 10, 32)
	require.NoError(t, err)
	gid, err := strconv.ParseUint(usr.Gid, 10, 32)
	require.NoError(t, err)
	return int(uid), int(gid)
}

func TestRootTransferDestinationOwnership(t *testing.T) {
	dir := t.TempDir()
	root := &syscall.SysProcAttr{Credential: &syscall.Credential{}}
	target := filepath.Join(dir, "file")
	if os.Geteuid() != 0 {
		require.ErrorContains(t, validateTransferDestination(target, root), "root-owned")
		return
	}
	require.NoError(t, validateTransferDestination(target, root))
	uid, gid := nobodyIDs(t)
	require.NoError(t, os.Chown(dir, uid, gid))
	require.ErrorContains(t, validateTransferDestination(target, root), "root-owned")
}

func TestRootTransferRejectsProcfs(t *testing.T) {
	root := &syscall.SysProcAttr{Credential: &syscall.Credential{}}
	for _, path := range []string{"/proc", "/proc/self/root/transfer-test", "/proc/" + strconv.Itoa(os.Getpid()) + "/cwd/transfer-test"} {
		t.Run(path, func(t *testing.T) {
			require.ErrorContains(t, validateTransferDestination(path, root), "cannot use procfs")
		})
	}
}

func TestRootTransferFollowsTrustedDirectoryLinks(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root-owned fixtures")
	}
	dir := t.TempDir()
	for _, name := range []string{"usr/lib", "usr/bin", "run", "var", "srv", "data/link", "writable", "sticky"} {
		require.NoError(t, os.MkdirAll(filepath.Join(dir, name), 0755))
	}
	for name, target := range map[string]string{
		"lib": "usr/lib", "bin": "usr/bin", "var/run": "../run",
		"srv/link":      filepath.Join(dir, "data/link"),
		"writable/link": "../run", "sticky/link": "../run",
		"srv/dangling": "../sticky/missing",
		"srv/loop":     "loop",
	} {
		require.NoError(t, os.Symlink(target, filepath.Join(dir, name)))
	}
	for _, name := range []string{"lib/x", "var/run/x", "bin/x", "srv/link/x"} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(dir, name)
			require.NoError(t, validateTransferDestination(path, nil))
			require.NoError(t, writeFileAs(t.Context(), path, strings.NewReader(name), nil, false))
		})
	}
	require.NoError(t, os.Chmod(filepath.Join(dir, "writable"), 0777))
	require.NoError(t, os.Chmod(filepath.Join(dir, "sticky"), os.ModeSticky|0777))
	assert.ErrorContains(t, validateTransferDestination(filepath.Join(dir, "writable/link/x"), nil), "writable only by root")
	assert.ErrorContains(t, validateTransferDestination(filepath.Join(dir, "sticky/link/x"), nil), "writable only by root")
	assert.ErrorIs(t, validateTransferDestination(filepath.Join(dir, "srv/dangling"), nil), os.ErrNotExist)
	assert.ErrorContains(t, validateTransferDestination(filepath.Join(dir, "srv/loop"), nil), "too many symbolic links")

	uid, gid := nobodyIDs(t)
	require.NoError(t, os.Chown(filepath.Join(dir, "data/link"), uid, gid))
	assert.ErrorContains(t, validateTransferDestination(filepath.Join(dir, "srv/link/x"), nil), "run the transfer as the directory's owner")
}

func TestFileExistsAsRequester(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires credential switching")
	}
	path := filepath.Join(t.TempDir(), "file")
	require.NoError(t, os.WriteFile(path, nil, 0600))
	uid, gid := nobodyIDs(t)
	attr := &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid)}}
	exists, err := fileExistsAs(t.Context(), path, attr)
	require.NoError(t, err)
	assert.False(t, exists)
	reader, _, err := readFileAs(t.Context(), path, attr)
	require.ErrorContains(t, err, "failed to stat source file")
	assert.Nil(t, reader)
	_, _, _, err = (&FileHandler{}).parsePaths(t.Context(), filepath.Dir(path), []string{path}, attr)
	assert.ErrorContains(t, err, "missing or inaccessible")
}

func TestFileExistsAsUsesShellBuiltin(t *testing.T) {
	path := filepath.Join(t.TempDir(), "file with spaces")
	require.NoError(t, os.WriteFile(path, nil, 0600))
	original := fileHelperCommand
	t.Cleanup(func() { fileHelperCommand = original })
	fileHelperCommand = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		assert.Equal(t, "/bin/sh", name)
		assert.Equal(t, []string{"-c", `test -e "$1" || test -L "$1"`, "sh", path}, args)
		return original(ctx, name, args...)
	}
	exists, err := fileExistsAs(t.Context(), path, &syscall.SysProcAttr{})
	require.NoError(t, err)
	assert.True(t, exists)
}

func TestFileDownloadRejectsDanglingDestinationSymlink(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("requires a non-root requester")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "destination")
	target := filepath.Join(dir, "target")
	require.NoError(t, os.Symlink(target, path))

	args := &common.CommandArgs{
		Path:           path,
		Type:           "text",
		Content:        "payload",
		AllowOverwrite: false,
	}
	code, message := (&FileHandler{}).fileDownload(t.Context(), args, &syscall.SysProcAttr{})
	assert.Equal(t, 1, code)
	assert.Equal(t, args.Path+" already exists.", message)
	_, err := os.Lstat(target)
	assert.ErrorIs(t, err, os.ErrNotExist)
}

func TestRootTransferRejectsMultipleLinks(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root transfer")
	}
	parent := t.TempDir()
	path := filepath.Join(parent, "existing")
	require.NoError(t, os.WriteFile(path, []byte("original"), 0600))
	require.NoError(t, os.Link(path, filepath.Join(parent, "second-link")))
	require.ErrorContains(t, validateTransferDestination(path, nil), "one link")
	require.NoError(t, os.Chmod(parent, os.ModeSticky|0777))
	require.ErrorContains(t, writeFileAs(t.Context(), path, strings.NewReader("updated"), nil, true), "one link")
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, "original", string(data))
}

func TestRootOnly_StickyDestinationHonorsOverwrite(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root transfer")
	}
	parent := t.TempDir()
	require.NoError(t, os.Chmod(parent, os.ModeSticky|0777))
	path := filepath.Join(parent, "staged")
	require.NoError(t, writeFileAs(t.Context(), path, strings.NewReader("one"), nil, false))
	require.ErrorIs(t, writeFileAs(t.Context(), path, strings.NewReader("two"), nil, false), os.ErrExist)
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, "one", string(data))
}

func TestFileDownloadAsRequesterWithoutOverwrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "download")
	handler := NewFileHandler(common.NewMockCommandExecutor(t), nil)
	attr := &syscall.SysProcAttr{}
	args := &common.CommandArgs{Type: "text", Path: path, Content: "payload"}

	code, msg := handler.fileDownload(t.Context(), args, attr)
	require.Zero(t, code, "%s", msg)

	args.Content = "replacement"
	code, msg = handler.fileDownload(t.Context(), args, attr)
	require.Equal(t, 1, code)
	assert.Equal(t, path+" already exists.", msg)
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, "payload", string(data))
}
