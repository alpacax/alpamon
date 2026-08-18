//go:build !windows

package runner

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStartTunnelRelayInvalidSessionID(t *testing.T) {
	tests := []struct {
		name      string
		sessionID string
	}{
		{name: "traversal pattern", sessionID: "../bad"},
		{name: "path separator", sessionID: "bad/session"},
		{name: "backslash separator", sessionID: `bad\session`},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			client := &TunnelClient{sessionID: tc.sessionID, ctx: context.Background()}

			err := client.startTunnelRelay()
			require.Error(t, err)
			assert.Contains(t, err.Error(), "invalid session ID")
			assert.Nil(t, client.daemonCmd)
			assert.Empty(t, client.daemonSocket)
		})
	}
}

func TestStartTunnelRelayClosedSession(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	client := &TunnelClient{sessionID: "session123", ctx: ctx}

	err := client.startTunnelRelay()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "closed before relay start")
	assert.Nil(t, client.daemonCmd)
}
