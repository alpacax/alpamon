package runner

import (
	"testing"
	"time"

	"github.com/alpacax/alpamon/v2/internal/protocol"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCommandRunnerEnvAndWorkSessionGates(t *testing.T) {
	for _, tc := range []struct {
		name      string
		state     string
		env       map[string]string
		wantReads int
		wantCalls int
	}{
		{
			name:  "refused env before control state",
			state: workSessionActive,
			env:   map[string]string{"LD_PRELOAD": "/tmp/preload.so"},
		},
		{
			name:      "admitted env in paused session",
			state:     workSessionPaused,
			env:       map[string]string{"LANG": "C.UTF-8"},
			wantReads: 1,
		},
		{
			name:      "admitted env in active session",
			state:     workSessionActive,
			env:       map[string]string{"LANG": "C.UTF-8"},
			wantReads: 1,
			wantCalls: 1,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := &fakeControlServer{}
			server.set(tc.state, 0)
			dispatcher := &fakeDispatcher{}
			runner := NewCommandRunner(nil, nil, protocol.Command{
				Shell:                "system",
				Line:                 "echo hello",
				Env:                  tc.env,
				WorkSessionID:        wsID,
				WorkSessionExpiresAt: wsNow.Add(time.Hour).Format(time.RFC3339),
			}, protocol.CommandData{}, dispatcher)
			runner.workSessions = newTestRegistry(server)

			require.NoError(t, runner.Run(t.Context()))
			require.Len(t, dispatcher.calls, tc.wantCalls)
			server.mu.Lock()
			reads := server.reads
			server.mu.Unlock()
			assert.Equal(t, tc.wantReads, reads)
			if tc.wantCalls != 0 {
				assert.Equal(t, tc.env, dispatcher.calls[0].args.Env)
			}
		})
	}
}
