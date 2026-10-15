//go:build !windows

package utils

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
)

// ListenUnixPrivate listens on a Unix socket at path that is never reachable with
// wider permissions than 0600. Closing the listener removes the socket unless
// another one has since replaced it.
func ListenUnixPrivate(path string) (net.Listener, error) {
	if err := RemoveSocket(path); err != nil {
		return nil, err
	}

	// Bound inside a 0700 directory and linked into place: a socket bound at its final
	// path would sit under the umask's mode until chmod, open to anyone who connects first.
	tmpDir, err := os.MkdirTemp(filepath.Dir(path), ".sock-")
	if err != nil {
		return nil, fmt.Errorf("failed to create private socket directory: %w", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	tmpPath := filepath.Join(tmpDir, "s")
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: tmpPath, Net: "unix"})
	if err != nil {
		return nil, fmt.Errorf("failed to listen on %s: %w", path, err)
	}
	ln.SetUnlinkOnClose(false) // The remembered temp path is gone once the socket is linked into place.

	// Taken from the temp path, which no one else can reach: after the link, path may
	// already hold another listener's socket. The hard link shares this inode.
	fi, err := os.Lstat(tmpPath)
	if err != nil {
		_ = ln.Close()
		return nil, fmt.Errorf("failed to stat socket %s: %w", tmpPath, err)
	}
	if err := moveSocketIntoPlace(tmpPath, path); err != nil {
		_ = ln.Close()
		return nil, err
	}
	return &privateListener{UnixListener: ln, path: path, info: fi}, nil
}

func moveSocketIntoPlace(tmpPath, path string) error {
	if err := os.Chmod(tmpPath, 0600); err != nil {
		return fmt.Errorf("failed to set socket permissions: %w", err)
	}
	if os.Geteuid() == 0 {
		if err := os.Chown(tmpPath, 0, 0); err != nil {
			return fmt.Errorf("failed to set socket ownership: %w", err)
		}
	}
	// Link, not rename: rename would replace whatever appeared at path after
	// RemoveSocket checked it, while link fails with EEXIST.
	if err := os.Link(tmpPath, path); err != nil {
		return fmt.Errorf("failed to publish socket at %s: %w", path, err)
	}
	return nil
}

type privateListener struct {
	*net.UnixListener
	path      string
	info      os.FileInfo // identity of the published socket; Close leaves a replacement alone
	closeOnce sync.Once
}

func (l *privateListener) Close() error {
	err := l.UnixListener.Close()
	l.closeOnce.Do(func() {
		if cur, statErr := os.Lstat(l.path); statErr == nil && os.SameFile(l.info, cur) {
			_ = RemoveSocket(l.path)
		}
	})
	return err
}
