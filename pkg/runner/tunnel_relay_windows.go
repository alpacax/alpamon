//go:build windows

package runner

import (
	"net"

	"github.com/rs/zerolog/log"
)

// startTunnelRelay is a no-op on Windows: streams are dialed directly in
// process, so there is no daemon to spawn. Alpamon runs single-privilege on
// Windows (see pkg/utils/privilege_windows.go), so a same-privilege daemon
// would add no isolation.
func (tc *TunnelClient) startTunnelRelay() error {
	log.Debug().Msgf("Tunnel relay ready for session %s (Windows - direct dial, no daemon).", tc.sessionID)
	return nil
}

// dialTunnelTarget dials the localhost target directly over TCP.
func (tc *TunnelClient) dialTunnelTarget(targetAddr string) (net.Conn, error) {
	return dialDirect(targetAddr)
}

// stopTunnelRelay is a no-op on Windows: there is no daemon process or socket.
func (tc *TunnelClient) stopTunnelRelay() {}
