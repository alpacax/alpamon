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
			assert.ErrorContains(t, h.Validate(cmd, nil), "unsupported_platform:")
			assert.ErrorContains(t, h.Validate(cmd, &common.CommandArgs{Username: "--invalid"}), "unsupported_platform:")
			assert.ElementsMatch(t, []string{"lockuser", "unlockuser"}, h.Commands())
			for _, args := range []*common.CommandArgs{nil, {Username: "--invalid"}, {Username: "deploy"}} {
				code, result, err := h.Execute(context.Background(), cmd, args)
				require.NoError(t, err)
				assert.Equal(t, 1, code)
				assert.Equal(t, "unsupported_platform: account locking requires Linux", result)
			}
			assert.Empty(t, mock.GetExecutedCommands())
		})
	}
}
