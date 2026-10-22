//go:build linux

package runner

import (
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

func peerCredentials(conn net.Conn) (peerCred, error) {
	var cred *unix.Ucred
	err := controlUnixConn(conn, func(fd int) error {
		var credErr error
		cred, credErr = unix.GetsockoptUcred(fd, unix.SOL_SOCKET, unix.SO_PEERCRED)
		if credErr != nil {
			return fmt.Errorf("failed to read SO_PEERCRED: %w", credErr)
		}
		return nil
	})
	if err != nil {
		return peerCred{}, err
	}
	return peerCred{uid: int(cred.Uid), pid: int(cred.Pid), pidKnown: true}, nil
}
