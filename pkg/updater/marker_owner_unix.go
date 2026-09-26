//go:build !windows

package updater

import (
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"
)

// readStateFile opens an upgrade state file (the marker or a guard result) without following a symlink and checks the
// opened file itself: a regular file, owned by this process's user, not
// writable by group or others. It then reads from the same handle.
func readStateFile(path string) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return nil, errors.New("upgrade state file is a symlink")
		}
		return nil, err
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("upgrade state file is not a regular file")
	}
	if info.Mode().Perm()&0o022 != 0 {
		return nil, errors.New("upgrade state file is writable by group or others")
	}
	if st, ok := info.Sys().(*syscall.Stat_t); ok && int(st.Uid) != os.Geteuid() {
		return nil, fmt.Errorf("upgrade state file is owned by uid %d", st.Uid)
	}
	data, err := io.ReadAll(io.LimitReader(f, maxMarkerSize+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxMarkerSize {
		return nil, errors.New("upgrade state file is too large")
	}
	return data, nil
}
