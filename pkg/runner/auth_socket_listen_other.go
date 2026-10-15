//go:build !linux

package runner

import (
	"net"

	"github.com/alpacax/alpamon/v2/pkg/utils"
)

func listenAuthSocket(path string) (net.Listener, error) {
	return utils.ListenUnixPrivate(path)
}
