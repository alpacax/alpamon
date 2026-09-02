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
	// codeql[go/path-injection]: Intentional - the path names a file the operator
	// asked to run on their own host, arriving over the authenticated channel that
	// already carries arbitrary command lines (the `system` shell), so it crosses
	// no privilege boundary and there is no root to confine it to. Payload
	// validation requires a POSIX-absolute path, and what bounds this lane is the
	// digest verified over the sealed copy before anything executes.
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0) // lgtm[go/path-injection]
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	return os.NewFile(uintptr(fd), path), nil
}
