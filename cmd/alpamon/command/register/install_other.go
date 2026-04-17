//go:build !windows

package register

// ensureInstalled is a no-op on Unix. Package managers (apt, brew)
// place the binary in the canonical location before `register` is
// invoked, so there is nothing for us to do.
func ensureInstalled() (relaunched bool, err error) {
	return false, nil
}
