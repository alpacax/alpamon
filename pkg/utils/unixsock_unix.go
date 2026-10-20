//go:build !windows

package utils

import (
	"fmt"
	"net"
	"os"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
)

// ListenUnixPrivate listens on a Unix socket at path that is never reachable with
// wider permissions than 0600. Closing the listener removes the socket only while it is
// still this one; the check and the unlink are not atomic, so a replacement can still go.
func ListenUnixPrivate(path string) (net.Listener, error) {
	if err := RemoveSocket(path); err != nil {
		return nil, err
	}
	return listenPrivateAt(path)
}

// listenPrivateAt binds at path itself, which fails instead of replacing whatever appeared
// there after RemoveSocket. Nothing can connect before listen, so mode and owner come first.
func listenPrivateAt(path string) (net.Listener, error) {
	fd, err := newPrivateSocket()
	if err != nil {
		return nil, fmt.Errorf("failed to create socket for %s: %w", path, err)
	}
	f := os.NewFile(uintptr(fd), path) // Owns fd from here; closed on every return.
	defer func() { _ = f.Close() }()

	if err := unix.Bind(fd, &unix.SockaddrUnix{Name: path}); err != nil {
		return nil, fmt.Errorf("failed to bind socket at %s: %w", path, err)
	}
	fi, err := os.Lstat(path)
	if err == nil {
		err = restrictBoundSocket(path, fi)
	}
	if err == nil {
		err = unix.Listen(fd, unix.SOMAXCONN)
	}
	var ln net.Listener
	if err == nil {
		ln, err = net.FileListener(f) // Dups fd, so closing f leaves the listener open.
	}
	if err != nil {
		if fi != nil {
			removeIfSame(path, fi)
		}
		return nil, fmt.Errorf("failed to listen on %s: %w", path, err)
	}
	return &privateListener{UnixListener: ln.(*net.UnixListener), path: path, info: fi}, nil
}

// restrictBoundSocket sets the bound socket's owner to root when running as root, without
// following a symlink; the mode is the platform's part, in setBoundSocketMode.
func restrictBoundSocket(path string, fi os.FileInfo) error {
	if err := setBoundSocketMode(path); err != nil {
		return fmt.Errorf("failed to set socket permissions: %w", err)
	}
	if os.Geteuid() != 0 {
		return nil
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && st.Uid == 0 && st.Gid == 0 {
		return nil
	}
	if err := os.Lchown(path, 0, 0); err != nil {
		return fmt.Errorf("failed to set socket ownership: %w", err)
	}
	return nil
}

func removeIfSame(path string, fi os.FileInfo) {
	if cur, err := os.Lstat(path); err == nil && os.SameFile(fi, cur) {
		_ = os.Remove(path) // Only a writer of the directory can swap it in between, and it could unlink it anyway.
	}
}

type privateListener struct {
	*net.UnixListener
	path      string
	info      os.FileInfo // identity of the published socket, checked by Close before unlinking
	closeOnce sync.Once
}

func (l *privateListener) Close() error {
	err := l.UnixListener.Close()
	l.closeOnce.Do(func() { removeIfSame(l.path, l.info) })
	return err
}
