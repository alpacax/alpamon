//go:build !linux && !darwin

package runner

import (
	"fmt"
	"net"
)

// peerCredentials always fails here: no auth.sock client exists on these
// platforms, so every connection is dropped.
func peerCredentials(conn net.Conn) (peerCred, error) {
	return peerCred{}, fmt.Errorf("auth socket peer credentials are not supported on this platform")
}
