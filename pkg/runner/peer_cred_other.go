//go:build !linux && !darwin

package runner

import (
	"errors"
	"net"
)

// peerCredentials always fails here: no auth.sock client exists on these
// platforms, so every connection is dropped.
func peerCredentials(net.Conn) (peerCred, error) {
	return peerCred{}, errors.New("auth socket peer credentials are not supported on this platform")
}
