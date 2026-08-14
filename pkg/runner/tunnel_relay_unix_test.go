//go:build !windows

package runner

import (
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
			client := &TunnelClient{sessionID: tc.sessionID}

			err := client.startTunnelRelay()
			require.Error(t, err)
			assert.Contains(t, err.Error(), "invalid session ID")
			assert.Nil(t, client.daemonCmd)
			assert.Empty(t, client.daemonSocket)
		})
	}
}
