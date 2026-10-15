//go:build windows

package utils

import (
	"net"
	"os"
)

// ListenUnixPrivate keeps the plain listen on Windows, where os.Chmod only toggles
// the read-only bit, so there is no permission window to close.
func ListenUnixPrivate(path string) (net.Listener, error) {
	_ = os.Remove(path)
	return net.Listen("unix", path)
}
