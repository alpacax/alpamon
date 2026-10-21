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

// privateListener removes its socket on Close only while the path is still this socket;
// the check and the unlink are not atomic, so a replacement can still go.
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
	if err != nil { // Without its identity the bound file cannot be told from a replacement, so it stays.
		return nil, fmt.Errorf("failed to stat bound socket at %s: %w", path, err)
	}
	ln, err := serveBoundSocket(f, fd, path, fi)
	if err != nil {
		removeIfSame(path, fi)
		return nil, err
	}
	return ln, nil
}

// serveBoundSocket restricts the socket fd, owned by f and bound at path, then listens on it.
func serveBoundSocket(f *os.File, fd int, path string, fi os.FileInfo) (net.Listener, error) {
	if err := restrictBoundSocket(path, fi); err != nil {
		return nil, err
	}
	if err := unix.Listen(fd, unix.SOMAXCONN); err != nil {
		return nil, fmt.Errorf("failed to listen on %s: %w", path, err)
	}
	ln, err := net.FileListener(f) // Dups fd, so closing f leaves the listener open.
	if err != nil {
		return nil, fmt.Errorf("failed to wrap listener for %s: %w", path, err)
	}
	ul, ok := ln.(*net.UnixListener)
	if !ok { // Unreachable for an AF_UNIX fd; checked so a change cannot panic here.
		_ = ln.Close()
		return nil, fmt.Errorf("unexpected listener type %T for %s", ln, path)
	}
	return &privateListener{UnixListener: ul, path: path, info: fi}, nil
}

// restrictBoundSocket sets the bound socket's owner to root when running as root, without
// following a symlink; the mode is the platform's part, in setBoundSocketMode.
func restrictBoundSocket(path string, fi os.FileInfo) error {
	if err := setBoundSocketMode(path); err != nil {
		return fmt.Errorf("failed to set permissions on socket %s: %w", path, err)
	}
	if os.Geteuid() != 0 {
		return nil
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && st.Uid == 0 && st.Gid == 0 {
		return nil // Already root:root; skipping the chown spares a setattr SELinux would have to allow.
	}
	if err := os.Lchown(path, 0, 0); err != nil {
		return fmt.Errorf("failed to set ownership on socket %s: %w", path, err)
	}
	return nil
}

func removeIfSame(path string, fi os.FileInfo) {
	if cur, err := os.Lstat(path); err == nil && os.SameFile(fi, cur) {
		_ = os.Remove(path) // Only a writer of the directory can swap it in between, and it could unlink it anyway.
	}
}
