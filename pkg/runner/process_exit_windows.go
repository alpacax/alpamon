package runner

import "errors"

// waitExit has no Windows form; code-server does not start there (code_server_windows.go).
func waitExit(pid int) error {
	return errors.ErrUnsupported
}
