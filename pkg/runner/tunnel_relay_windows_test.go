//go:build windows

package runner

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWindowsTunnelRelay(t *testing.T) {
	t.Run("startTunnelRelay succeeds without a daemon", func(t *testing.T) {
		tc := &TunnelClient{sessionID: "session123"}

		require.NoError(t, tc.startTunnelRelay())
		assert.Nil(t, tc.daemonCmd)
		assert.Empty(t, tc.daemonSocket)
	})

	t.Run("dialTunnelTarget rejects non-localhost", func(t *testing.T) {
		tc := &TunnelClient{sessionID: "session123"}

		conn, err := tc.dialTunnelTarget("10.0.0.1:80")
		require.Error(t, err)
		assert.Nil(t, conn)
	})

	t.Run("stopTunnelRelay is safe with no daemon", func(t *testing.T) {
		tc := &TunnelClient{sessionID: "session123"}

		assert.NotPanics(t, func() { tc.stopTunnelRelay() })
	})
}
