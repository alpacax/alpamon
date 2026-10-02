package runner

import (
	"sync"
	"syscall"
	"time"

	"github.com/rs/zerolog/log"
	"golang.org/x/sys/unix"
)

// tcpUserTimeout caps unacknowledged sends, which Linux otherwise retries for tcp_retries2 (~15 min at the default).
// Keepalive bounds reads only after the first pong; this also bounds the link before it and writes with no deadline.
const tcpUserTimeout = 45 * time.Second

var warnTCPUserTimeoutOnce sync.Once // the kernel's answer never changes, so one warning per process is enough

// setTCPUserTimeout is a net.Dialer Control hook that caps how long sent data
// may stay unacknowledged before the kernel aborts the connection.
func setTCPUserTimeout(_, _ string, c syscall.RawConn) error {
	var sockErr error
	if err := c.Control(func(fd uintptr) {
		sockErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_USER_TIMEOUT, int(tcpUserTimeout.Milliseconds()))
	}); err != nil {
		return err
	}
	if sockErr != nil {
		// A kernel without the option still gets the read deadlines, so it is no reason to refuse the dial.
		warnTCPUserTimeoutOnce.Do(func() {
			log.Warn().Err(sockErr).Msg("Failed to set TCP_USER_TIMEOUT; a dead connection may take the kernel's retransmission limit to notice.")
		})
	}
	return nil
}
