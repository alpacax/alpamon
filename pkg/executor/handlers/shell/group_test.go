package shell

import (
	"testing"

	"github.com/alpacax/alpamon/v2/pkg/executor/handlers/common"
	"github.com/stretchr/testify/assert"
)

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
