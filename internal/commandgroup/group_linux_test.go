package commandgroup

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConfigureAndFallback(t *testing.T) {
	file, err := os.Open(t.TempDir())
	require.NoError(t, err)
	defer func() { require.NoError(t, file.Close()) }()
	cmd := &exec.Cmd{SysProcAttr: &syscall.SysProcAttr{Setsid: true}}
	Configure(context.WithValue(t.Context(), groupKey{}, file), cmd)
	require.True(t, cmd.SysProcAttr.UseCgroupFD)
	assert.Equal(t, int(file.Fd()), cmd.SysProcAttr.CgroupFD)
	assert.False(t, Unsupported(cmd, &os.PathError{Op: "fork/exec", Err: syscall.EIO}))
	assert.True(t, Unsupported(cmd, &os.PathError{Op: "fork/exec", Err: syscall.ENOSYS}))
	assert.False(t, cmd.SysProcAttr.UseCgroupFD)
	assert.True(t, cmd.SysProcAttr.Setsid)
}

func TestPrepareFallback(t *testing.T) {
	for _, tc := range []struct {
		name, groupFile         string
		controllers, wantCreate bool
	}{
		{"legacy hierarchy", "1:name=systemd:/agent", true, false},
		{"missing controllers", "0::/agent", false, false},
		{"read-only hierarchy", "0::/agent", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			require.NoError(t, os.Mkdir(filepath.Join(root, "agent"), 0700))
			if tc.controllers {
				require.NoError(t, os.WriteFile(filepath.Join(root, "agent", "cgroup.controllers"), nil, 0600))
			}
			created := false
			ctx, group, finish := prepare(t.Context(), unifiedPath(tc.groupFile), root, func(string, string) (string, error) { created = true; return "", syscall.EROFS })
			defer finish()
			assert.Equal(t, tc.wantCreate, created)
			assert.Empty(t, group)
			assert.Nil(t, ctx.Value(groupKey{}))
		})
	}
}

func TestCleanupEmptyOwnedGroups(t *testing.T) {
	base := t.TempDir()
	const attribute = "user.alpamon.test"
	empty := filepath.Join(base, prefix+"empty")
	busy := filepath.Join(base, prefix+"busy")
	foreign := filepath.Join(base, prefix+"foreign")
	for _, dir := range []string{empty, busy, foreign} {
		require.NoError(t, os.Mkdir(dir, 0700))
	}
	for _, dir := range []string{empty, busy} {
		require.NoError(t, unix.Setxattr(dir, attribute, []byte{1}, unix.XATTR_CREATE))
	}
	require.NoError(t, os.Mkdir(filepath.Join(busy, "child"), 0700))
	cleanupEmpty(base, attribute)
	_, err := os.Stat(empty)
	assert.ErrorIs(t, err, os.ErrNotExist)
	assert.DirExists(t, busy)
	assert.DirExists(t, foreign)
}
