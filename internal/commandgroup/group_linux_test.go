package commandgroup

import (
	"context"
	"os"
	"os/exec"
	"syscall"
	"testing"

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
	assert.False(t, Unsupported(cmd, &os.PathError{Op: "fork/exec", Err: syscall.ENOENT}))
	assert.True(t, Unsupported(cmd, &os.PathError{Op: "fork/exec", Err: syscall.ENOSYS}))
	assert.False(t, cmd.SysProcAttr.UseCgroupFD)
	assert.True(t, cmd.SysProcAttr.Setsid)
}
