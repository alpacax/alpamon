//go:build !linux

package user

import (
	"context"
	"testing"

	"github.com/alpacax/alpamon/v2/pkg/executor/handlers/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAccountLockUnsupported(t *testing.T) {
	for _, cmd := range []string{"lockuser", "unlockuser"} {
		t.Run(cmd, func(t *testing.T) {
			mock := common.NewMockCommandExecutor(t)
			h := NewUnsupportedAccountLockHandler(mock)
			assert.ElementsMatch(t, []string{"lockuser", "unlockuser"}, h.Commands())
			code, result, err := h.Execute(context.Background(), cmd, &common.CommandArgs{Username: "deploy"})
			require.NoError(t, err)
			assert.Equal(t, 1, code)
			assert.Equal(t, "unsupported_platform: account locking requires Linux", result)
			assert.Empty(t, mock.GetExecutedCommands())
		})
	}
}
