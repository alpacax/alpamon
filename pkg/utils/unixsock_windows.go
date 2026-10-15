//go:build windows

package utils

import "net"

// ListenUnixPrivate keeps the plain listen on Windows, where os.Chmod only toggles
// the read-only bit. A stale socket is removed first, but a regular file is refused.
func ListenUnixPrivate(path string) (net.Listener, error) {
	if err := RemoveSocket(path); err != nil {
		return nil, err
	}
	return net.Listen("unix", path)
}
