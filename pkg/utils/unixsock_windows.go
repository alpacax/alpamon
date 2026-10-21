//go:build windows

package utils

import "net"

// listenPrivateAt keeps the plain listen on Windows, where os.Chmod only toggles
// the read-only bit.
func listenPrivateAt(path string) (net.Listener, error) {
	return net.Listen("unix", path)
}
