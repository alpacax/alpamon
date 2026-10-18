//go:build !linux

package runner

import "net"

func listenAuthSocket(path string) (net.Listener, error) {
	return net.Listen("unix", path)
}
