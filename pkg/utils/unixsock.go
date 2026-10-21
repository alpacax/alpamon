package utils

import (
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
)

// ListenUnixPrivate listens on a Unix socket at path, replacing a stale socket there.
// Off Windows the socket is never reachable with wider permissions than 0600.
func ListenUnixPrivate(path string) (net.Listener, error) {
	if err := RemoveSocket(path); err != nil {
		return nil, err
	}
	return listenPrivateAt(path)
}

// RemoveSocket deletes the Unix socket at path; a missing path is not an error.
// A symlink or non-socket file is refused; a file swapped in after the check is not.
func RemoveSocket(path string) error {
	fi, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("failed to stat socket %s: %w", path, err)
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing to remove symlink at %s", path)
	}
	if fi.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("refusing to remove non-socket file at %s", path)
	}
	return os.Remove(path)
}
