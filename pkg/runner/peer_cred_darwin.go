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
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return peerCred{}, fmt.Errorf("auth socket connection is %T, not a Unix connection", conn)
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return peerCred{}, err
	}
	var cred *unix.Xucred
	var credErr error
	if err := raw.Control(func(fd uintptr) {
		cred, credErr = unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	}); err != nil {
		return peerCred{}, err
	}
	if credErr != nil {
		return peerCred{}, fmt.Errorf("failed to read LOCAL_PEERCRED: %w", credErr)
	}
	return peerCred{uid: int(cred.Uid)}, nil
}
