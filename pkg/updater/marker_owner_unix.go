//go:build !windows

package updater

import (
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"
)

// readMarker opens the marker without following a symlink and checks the
// opened file itself: a regular file, owned by this process's user, not
// writable by group or others. It then reads from the same handle.
func readMarker(path string) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return nil, errors.New("upgrade marker is a symlink")
		}
		return nil, err
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("upgrade marker is not a regular file")
	}
	if info.Mode().Perm()&0o022 != 0 {
		return nil, errors.New("upgrade marker is writable by group or others")
	}
	if st, ok := info.Sys().(*syscall.Stat_t); ok && int(st.Uid) != os.Geteuid() {
		return nil, fmt.Errorf("upgrade marker is owned by uid %d", st.Uid)
	}
	return io.ReadAll(io.LimitReader(f, maxMarkerSize))
}
