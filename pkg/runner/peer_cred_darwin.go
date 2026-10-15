//go:build darwin

package runner

import (
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

// peerCredentials reports the UID only: alpamon-pam does not target macOS, so
// there is no PAM producer whose claimed pid could be compared.
func peerCredentials(conn net.Conn) (peerCred, error) {
	var cred *unix.Xucred
	err := controlUnixConn(conn, func(fd int) error {
		var credErr error
		cred, credErr = unix.GetsockoptXucred(fd, unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
		if credErr != nil {
			return fmt.Errorf("failed to read LOCAL_PEERCRED: %w", credErr)
		}
		return nil
	})
	if err != nil {
		return peerCred{}, err
	}
	return peerCred{uid: int(cred.Uid)}, nil
}
