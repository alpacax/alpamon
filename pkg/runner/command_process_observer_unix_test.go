//go:build !windows

package runner

import (
	"context"
	"testing"

	"github.com/alpacax/alpamon/v2/internal/protocol"
	"github.com/alpacax/alpamon/v2/pkg/executor/handlers/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAdmitWorkSession_BindsProcessObserverForNonShellCommands(t *testing.T) {
	for _, executionID := range []string{"", "command-1"} {
		t.Run("executionID="+executionID, func(t *testing.T) {
			server := &fakeControlServer{}
			server.set(workSessionActive, 0)
			registry := newTestRegistry(server)
			cr := &CommandRunner{
				command: protocol.Command{
					ID: "command-1", Line: "remove",
					WorkSessionID: wsID,
				},
				workSessions: registry,
			}
			ctx, release, err := cr.admitWorkSession(context.Background())
			require.NoError(t, err)
			defer release()
			observer := common.ProcessObserverFromContext(ctx)
			require.NotNil(t, observer, "non-shell commands need process observation even when Exec has no command ID")
			cmd := startSession(t, "sleep", "60")
			observer(executionID, cmd.Process.Pid)
			registry.mu.Lock()
			work := registry.sessions[wsID].owned()
			registry.mu.Unlock()
			require.Len(t, work.Sessions, 1)
			assert.Equal(t, cmd.Process.Pid, work.Sessions[0].SID)
			assert.Equal(t, "command-1", work.Sessions[0].CommandID)
			assert.Equal(t, ownedKindCommand, work.Sessions[0].Kind)
		})
	}
}
