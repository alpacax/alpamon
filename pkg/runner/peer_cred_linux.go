//go:build linux

package runner

import (
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

func peerCredentials(conn net.Conn) (peerCred, error) {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return peerCred{}, fmt.Errorf("auth socket connection is %T, not a Unix connection", conn)
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return peerCred{}, err
	}
	var cred *unix.Ucred
	var credErr error
	if err := raw.Control(func(fd uintptr) {
		cred, credErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return peerCred{}, err
	}
	if credErr != nil {
		return peerCred{}, fmt.Errorf("failed to read SO_PEERCRED: %w", credErr)
	}
	return peerCred{uid: int(cred.Uid), pid: int(cred.Pid), pidKnown: true}, nil
}
