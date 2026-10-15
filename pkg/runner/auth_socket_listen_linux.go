//go:build linux

package runner

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"

	"github.com/alpacax/alpamon/v2/pkg/utils"
	"github.com/rs/zerolog/log"
	"golang.org/x/sys/unix"
)

// authSocketContext is the SELinux context of the auth.sock listener. The
// alpamon-pam policy module defines the type and lets confined sudo, sshd and
// login connect to sockets of it, so they reach this socket and no other
// socket held by an unconfined process. Without the module the type is
// unknown, setting it fails, and the listener keeps the process's label.
const authSocketContext = "system_u:system_r:alpamon_auth_t:s0"

// sockcreateLabeler holds the steps listenUnixLabeled takes, so tests can
// replace them.
type sockcreateLabeler struct {
	enabled func() bool
	write   func(context string) error
	listen  func(network, address string) (net.Listener, error)
}

func listenAuthSocket(path string) (net.Listener, error) {
	return listenUnixLabeled(path, sockcreateLabeler{
		enabled: func() bool {
			_, err := os.Stat("/sys/fs/selinux/enforce")
			return err == nil
		},
		write:  writeSockcreateContext,
		listen: listenUnixPrivate,
	})
}

func listenUnixPrivate(_, address string) (net.Listener, error) {
	return utils.ListenUnixPrivate(address)
}

// writeSockcreateContext sets the context the calling thread gives the sockets
// it creates; "" restores the default. It uses the per-task path because
// /proc/thread-self does not exist on 3.10 kernels.
func writeSockcreateContext(context string) error {
	path := fmt.Sprintf("/proc/self/task/%d/attr/sockcreate", unix.Gettid())
	fd, err := unix.Open(path, unix.O_WRONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open %s: %w", path, err)
	}

	data := []byte(context)
	if context == "" {
		data = nil
	}
	n, writeErr := unix.Write(fd, data)
	closeErr := unix.Close(fd)
	if writeErr != nil {
		return fmt.Errorf("write %s: %w", path, writeErr)
	}
	if n != len(context) {
		return fmt.Errorf("write %s: %w", path, io.ErrShortWrite)
	}
	if closeErr != nil {
		return fmt.Errorf("close %s: %w", path, closeErr)
	}
	return nil
}

// listenUnixLabeled listens on path with authSocketContext where SELinux is
// enabled. The context is set, used and cleared on one locked OS thread, so no
// other socket gets it. Any failure to label falls back to an unlabeled one.
// Every listener comes from utils.ListenUnixPrivate, so it is never wider than 0600.
func listenUnixLabeled(path string, l sockcreateLabeler) (net.Listener, error) {
	if !l.enabled() {
		return utils.ListenUnixPrivate(path)
	}

	type result struct {
		listener net.Listener
		err      error
	}
	results := make(chan result, 1)
	go func() {
		// The thread is unlocked only after a clear that succeeded. On any
		// failure the goroutine returns still locked, so the runtime ends its
		// OS thread along with whatever socket context a failed write left.
		runtime.LockOSThread()
		if err := l.write(authSocketContext); err != nil {
			results <- result{err: err}
			return
		}

		listener, listenErr := l.listen("unix", path)
		clearErr := l.write("")
		if clearErr == nil {
			runtime.UnlockOSThread()
		}
		results <- result{listener: listener, err: errors.Join(listenErr, clearErr)}
	}()

	res := <-results
	if res.listener != nil {
		log.Debug().Err(res.err).Str("context", authSocketContext).Msg("Created auth socket listener with SELinux context")
		return res.listener, nil
	}

	log.Debug().Err(res.err).Msg("Auth socket keeps the process's default label")
	return utils.ListenUnixPrivate(path) // Also clears a socket the failed listen left at path.
}
