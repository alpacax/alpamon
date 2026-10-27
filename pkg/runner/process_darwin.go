//go:build darwin

package runner

import (
	"errors"

	"golang.org/x/sys/unix"
)

// waitExit blocks until pid exits and leaves it unreaped: darwin has no waitid, and a
// kqueue NOTE_EXIT reports the exit without collecting it.
func waitExit(pid int) error {
	kq, err := unix.Kqueue()
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(kq) }()

	var change unix.Kevent_t
	unix.SetKevent(&change, pid, unix.EVFILT_PROC, unix.EV_ADD|unix.EV_ONESHOT)
	change.Fflags = unix.NOTE_EXIT
	events := make([]unix.Kevent_t, 1)
	for {
		n, err := unix.Kevent(kq, []unix.Kevent_t{change}, events, nil)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return err
		}
		if n == 0 {
			continue
		}
		if events[0].Flags&unix.EV_ERROR == 0 {
			return nil
		}
		// ESRCH: the pid is already a zombie, which only our own Wait can collect.
		if errno := unix.Errno(events[0].Data); errno != unix.ESRCH {
			return errno
		}
		return nil
	}
}
