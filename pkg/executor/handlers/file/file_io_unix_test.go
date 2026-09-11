//go:build !windows

package file

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"testing/iotest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWriteFileAs_TeePath_CreatesParentDir(t *testing.T) {
	for _, dir := range []string{"nested/deep", "space and 'quote'/$literal;name"} {
		t.Run(strings.ReplaceAll(dir, "/", "_"), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), dir, "out 'file'.bin")
			// Select the subprocess branch without changing credentials or requiring root.
			err := writeFileAs(t.Context(), path, strings.NewReader("payload"), &syscall.SysProcAttr{})
			require.NoError(t, err)
			assert.DirExists(t, filepath.Dir(path))
			got, err := os.ReadFile(path)
			require.NoError(t, err)
			assert.Equal(t, "payload", string(got))

			err = writeFileAs(t.Context(), path, strings.NewReader("next"), &syscall.SysProcAttr{})
			require.NoError(t, err)
			got, err = os.ReadFile(path)
			require.NoError(t, err)
			assert.Equal(t, "next", string(got))
		})
	}
}

func TestWriteFileAs_RejectsNonAbsolutePath(t *testing.T) {
	err := writeFileAs(t.Context(), "relative/x", strings.NewReader("payload"), nil)
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

	err := writeFileAs(t.Context(), path, strings.NewReader("payload"), &syscall.SysProcAttr{})
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

	err := writeFileAs(t.Context(), path, strings.NewReader("payload"), &syscall.SysProcAttr{})
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

	err := writeFileAs(t.Context(), path, strings.NewReader("payload"), &syscall.SysProcAttr{})
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

	err := writeFileAs(t.Context(), path, iotest.ErrReader(errors.New("connection reset")), &syscall.SysProcAttr{})
	require.Error(t, err)
	got, readErr := os.ReadFile(path)
	require.NoError(t, readErr)
	assert.Equal(t, "ORIGINAL", string(got))
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

func TestDirTreeIsAllDirs(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "nested"), 0755))
	assert.True(t, dirTreeIsAllDirs(dir))

	require.NoError(t, os.WriteFile(filepath.Join(dir, "nested", "out.bin"), []byte("x"), 0644))
	assert.False(t, dirTreeIsAllDirs(dir))
}

func TestWriteFileAs_TeePath_RemovesDirsItCreatedOnFailure(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "new", "nested", "out.bin")

	err := writeFileAs(t.Context(), path, iotest.ErrReader(errors.New("boom")), &syscall.SysProcAttr{})
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

	err := writeFileAs(t.Context(), path, iotest.ErrReader(errors.New("boom")), &syscall.SysProcAttr{})
	require.Error(t, err)
	assert.ErrorContains(t, err, "boom")
	assert.DirExists(t, sub)
}

func TestWriteFileAs_DemotedPath_CreatesParentsAsUser(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("credential demotion requires root")
	}
	// Only the demoted user should own the newly created parents.
	const uid, gid = 65534, 65534
	dir := t.TempDir()
	parent := filepath.Dir(dir)
	parentInfo, err := os.Stat(parent)
	require.NoError(t, err)
	require.NoError(t, os.Chmod(parent, 0755))
	t.Cleanup(func() { require.NoError(t, os.Chmod(parent, parentInfo.Mode().Perm())) })
	require.NoError(t, os.Chown(dir, uid, gid))
	attr := &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uid, Gid: gid}}
	path := filepath.Join(dir, "nested", "deep", "out.bin")

	require.NoError(t, writeFileAs(t.Context(), path, strings.NewReader("payload"), attr))
	for _, created := range []string{filepath.Join(dir, "nested"), filepath.Dir(path), path} {
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
