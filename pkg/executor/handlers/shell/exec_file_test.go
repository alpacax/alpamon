package shell

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/alpacax/alpamon/v2/pkg/executor/handlers/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// openTempFile stands in for the descriptor the runner opens and verifies
// before dispatch.
func openTempFile(t *testing.T) *os.File {
	t.Helper()
	path := filepath.Join(t.TempDir(), "deploy.sh")
	require.NoError(t, os.WriteFile(path, []byte("printf 'ok\\n'\n"), 0o700))
	file, err := os.Open(path)
	require.NoError(t, err)
	t.Cleanup(func() { _ = file.Close() })
	return file
}

func TestShellHandler_ExecFile_ForwardsDescriptorAndArgs(t *testing.T) {
	mockExec := common.NewMockCommandExecutor(t)
	handler := NewShellHandler(mockExec)
	file := openTempFile(t)
	execArgs := []string{"/bin/bash", "/proc/self/fd/3", "--fast", "a b"}

	exitCode, _, err := handler.Execute(context.Background(), common.ExecFile.String(), &common.CommandArgs{
		VerifiedFile: file,
		ExecArgs:     execArgs,
		Username:     "deploy",
	})

	require.NoError(t, err)
	assert.Equal(t, 0, exitCode)

	executed := mockExec.GetExecutedCommands()
	require.Len(t, executed, 1)
	assert.Same(t, file, executed[0].File, "the child must inherit the verified descriptor itself")
	assert.Equal(t, execArgs[0], executed[0].Name)
	assert.Equal(t, execArgs[1:], executed[0].Args)
	assert.Equal(t, "deploy", executed[0].User)
	assert.Equal(t, common.ShellTimeout, executed[0].Timeout)
}

// Validation is the last guard before exec: without a descriptor there is
// nothing verified to run, so the handler must refuse rather than fall through
// to some path-shaped argument.
func TestShellHandler_ExecFile_ValidateRequiresDescriptorAndArgs(t *testing.T) {
	handler := NewShellHandler(common.NewMockCommandExecutor(t))

	tests := []struct {
		name string
		args *common.CommandArgs
	}{
		{
			name: "no descriptor",
			args: &common.CommandArgs{ExecArgs: []string{"/bin/bash", "/proc/self/fd/3"}},
		},
		{
			name: "no argv",
			args: &common.CommandArgs{VerifiedFile: openTempFile(t)},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Error(t, handler.Validate(common.ExecFile.String(), tt.args))
		})
	}
}

func TestShellHandler_ExecFile_ValidateAcceptsCompleteArgs(t *testing.T) {
	handler := NewShellHandler(common.NewMockCommandExecutor(t))

	err := handler.Validate(common.ExecFile.String(), &common.CommandArgs{
		VerifiedFile: openTempFile(t),
		ExecArgs:     []string{"/bin/bash", "/proc/self/fd/3"},
	})

	assert.NoError(t, err)
}
