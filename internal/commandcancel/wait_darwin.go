package commandcancel

import (
	"errors"

	"golang.org/x/sys/unix"
)

// WaitExited uses NOTE_EXIT because Darwin waitid can return for stopped processes.
func WaitExited(pid int) error {
	fd, err := unix.Kqueue()
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	change := unix.Kevent_t{Ident: uint64(pid), Filter: unix.EVFILT_PROC, Flags: unix.EV_ADD | unix.EV_ONESHOT, Fflags: unix.NOTE_EXIT}
	// ESRCH means the still-unreaped child has already exited.
	for {
		_, err = unix.Kevent(fd, []unix.Kevent_t{change}, nil, nil)
		if err != unix.EINTR {
			break
		}
	}
	if errors.Is(err, unix.ESRCH) {
		return nil
	}
	if err != nil {
		return err
	}
	events := make([]unix.Kevent_t, 1)
	for {
		_, err = unix.Kevent(fd, nil, events, nil)
		if err != unix.EINTR {
			return err
		}
	}
}
