//go:build windows

package executor

import "errors"

// StartDetached is not implemented on Windows, where nothing needs to outlive the agent this way.
func (e *Executor) StartDetached(_ string, _ ...string) error {
	return errors.New("starting a detached command is not supported on Windows")
}
