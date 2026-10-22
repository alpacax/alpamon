//go:build linux || darwin

package runner

import (
	"fmt"
	"net"
)

// controlUnixConn runs fn with the connection's raw fd, which is valid only inside fn.
func controlUnixConn(conn net.Conn, fn func(fd int) error) error {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return fmt.Errorf("auth socket connection is %T, not a Unix connection", conn)
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return err
	}
	var fnErr error
	if err := raw.Control(func(fd uintptr) { fnErr = fn(int(fd)) }); err != nil {
		return err
	}
	return fnErr
}
