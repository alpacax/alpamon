//go:build !windows

package runner

import (
	"os"

	"golang.org/x/sys/unix"
)

// openEntrypoint opens the submitted path for reading without blocking.
//
// O_NONBLOCK is the whole point. A read-only open of a FIFO blocks until a
// writer appears, and this runs before dispatcher.Execute, so no ShellTimeout
// deadline covers it: a requester could mkfifo a path in its own account and
// park the runner goroutine forever, leaking a goroutine and a descriptor per
// attempt with nothing to bound it. The flag is a no-op on regular files,
// which is the only kind the caller proceeds with.
//
// O_CLOEXEC keeps this descriptor out of the child; the child receives the
// sealed copy through ExtraFiles instead.
func openEntrypoint(path string) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	return os.NewFile(uintptr(fd), path), nil
}
