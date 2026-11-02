//go:build !linux && !darwin && !windows

package runner

import "fmt"

func editorPeerUID(fd int) (uint32, error) {
	return 0, fmt.Errorf("editor socket peer credentials are unsupported on this platform")
}
