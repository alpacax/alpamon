//go:build windows

package runner

import (
	"fmt"
	"net"
)

func (tc *TunnelClient) startTunnelRelay() error {
	return fmt.Errorf("tunnel is not supported on Windows")
}

func (tc *TunnelClient) dialTunnelTarget(targetAddr string) (net.Conn, error) {
	return nil, fmt.Errorf("tunnel is not supported on Windows")
}

func (tc *TunnelClient) stopTunnelRelay() {}
