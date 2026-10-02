//go:build !linux

package runner

import "syscall"

// setTCPUserTimeout is nil outside Linux, which leaves the socket at the platform's own retransmission limit.
var setTCPUserTimeout func(network, address string, c syscall.RawConn) error
