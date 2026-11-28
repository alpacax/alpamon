package commandcancel

import (
	"errors"
	"os"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
)

var linuxPidfd = &pidfdOps{
	open:  func(pid int) (int, error) { return unix.PidfdOpen(pid, 0) },
	send:  func(fd int, sig syscall.Signal) error { return unix.PidfdSendSignal(fd, sig, nil, 0) },
	close: unix.Close,
}

// pidfdAvailable probes alpamon's own process once. A kernel older than 5.3
// answers ENOSYS, and a seccomp filter that blocks the calls answers EPERM.
var pidfdAvailable = sync.OnceValue(func() bool {
	fd, err := unix.PidfdOpen(os.Getpid(), 0)
	if err == nil {
		defer func() { _ = unix.Close(fd) }()
		err = unix.PidfdSendSignal(fd, 0, nil, 0)
	}
	return !errors.Is(err, unix.ENOSYS) && !errors.Is(err, unix.EPERM)
})

func systemPidfd() *pidfdOps {
	if !pidfdAvailable() {
		return nil
	}
	return linuxPidfd
}
