//go:build windows

package runner

import (
	"net"

	"github.com/rs/zerolog/log"
)

// startTunnelRelay is a no-op: streams are dialed in process. Alpamon runs
// single-privilege on Windows (see pkg/utils/privilege_windows.go), so a
// same-privilege daemon would add no isolation.
func (tc *TunnelClient) startTunnelRelay() error {
	log.Info().Msgf("Tunnel relay ready for session %s (Windows - direct dial, no daemon).", tc.sessionID)
	return nil
}

func (tc *TunnelClient) dialTunnelTarget(targetAddr string) (net.Conn, error) {
	return dialDirect(targetAddr)
}

// stopTunnelRelay is a no-op: no daemon process or socket exists.
func (tc *TunnelClient) stopTunnelRelay() {}
