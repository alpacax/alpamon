package shell

import (
	"context"
	"testing"

	"github.com/alpacax/alpamon/v2/pkg/executor/handlers/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestShellHandler_EmptyGroupRefused(t *testing.T) {
	for _, command := range []common.CommandType{common.ShellCmd, common.Exec, common.ExecFile} {
		for _, streaming := range []bool{false, true} {
			t.Run(command.String()+map[bool]string{false: "/result", true: "/streaming"}[streaming], func(t *testing.T) {
				mockExec := common.NewMockCommandExecutor(t)
				handler := NewShellHandler(mockExec)
				args := &common.CommandArgs{
					Command:  "echo hi",
					Username: "testuser",
					ExecArgs: []string{"/bin/bash", "/proc/self/fd/3"},
				}
				var chunks []string
				if streaming {
					args.ChunkCallback = func(_ context.Context, content string) {
						chunks = append(chunks, content)
					}
				}

				code, output, err := handler.Execute(context.Background(), command.String(), args)

				require.NoError(t, err)
				assert.Equal(t, 1, code)
				assert.Equal(t, "groupname is required", output)
				assert.Empty(t, mockExec.GetExecutedCommands())
				if streaming {
					assert.Equal(t, []string{output}, chunks)
				}
			})
		}
	}
}

func TestShellHandler_ValidateEmptyGroup(t *testing.T) {
	handler := NewShellHandler(common.NewMockCommandExecutor(t))
	for _, command := range []common.CommandType{common.ShellCmd, common.Exec, common.ExecFile} {
		t.Run(command.String(), func(t *testing.T) {
			args := &common.CommandArgs{
				Command:      "echo hi",
				VerifiedFile: openTempFile(t),
				ExecArgs:     []string{"/bin/bash", "/proc/self/fd/3"},
			}

			assert.EqualError(t, handler.Validate(command.String(), args), "groupname is required")
		})
	}
}
