//go:build darwin

package runner

import (
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

func peerCredentials(conn net.Conn) (peerCred, error) {
	var cred *unix.Xucred
	var pid int
	err := controlUnixConn(conn, func(fd int) error {
		var credErr error
		cred, credErr = unix.GetsockoptXucred(fd, unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
		if credErr != nil {
			return fmt.Errorf("failed to read LOCAL_PEERCRED: %w", credErr)
		}
		// Unlike SO_PEERCRED, LOCAL_PEERPID is the last process to use the peer socket, not its
		// connector, so a child handed the fd is reported once it writes; the uid stays connect-time.
		pid, credErr = unix.GetsockoptInt(fd, unix.SOL_LOCAL, unix.LOCAL_PEERPID)
		if credErr != nil {
			return fmt.Errorf("failed to read LOCAL_PEERPID: %w", credErr)
		}
		return nil
	})
	if err != nil {
		return peerCred{}, err
	}
	return peerCred{uid: int(cred.Uid), pid: pid}, nil
}
