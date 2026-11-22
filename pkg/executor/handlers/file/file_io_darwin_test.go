//go:build darwin

package file

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWriteFileAsNonOverwriteUsesTee(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "download")
	original := fileHelperCommand
	t.Cleanup(func() { fileHelperCommand = original })
	var commands [][]string
	fileHelperCommand = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		commands = append(commands, append([]string{name}, args...))
		return original(ctx, name, args...)
	}

	require.NoError(t, writeFileAs(t.Context(), path, strings.NewReader("payload"), &syscall.SysProcAttr{}, false))
	require.Len(t, commands, 1)
	require.Len(t, commands[0], 3)
	assert.Equal(t, []string{"/bin/sh", "-c"}, commands[0][:2])
	assert.Contains(t, commands[0][2], "mkdir -p ")
	assert.Contains(t, commands[0][2], "tee ")
	assert.Contains(t, commands[0][2], "rm -f ")
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, "payload", string(data))
}
