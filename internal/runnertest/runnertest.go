// Package runnertest provides test-only glue around pkg/runner. It is
// split out so that the runner package itself does not need to import
// "testing" (which would otherwise leak test-only API surface and the
// testing dependency into shipped binaries).
//
// It lives under the repo-root internal/ tree so the Go compiler blocks
// imports from outside this module, preventing accidental use of the
// singleton-swap helper from external consumers.
//
// This package must only be imported from *_test.go files.
package runnertest

import (
	"testing"

	"github.com/alpacax/alpamon/v2/pkg/runner"
)

// NewAuthManager returns an AuthManager populated just enough to
// exercise the PID tracker. It does not start the socket listener.
func NewAuthManager() *runner.AuthManager {
	return runner.NewEmptyAuthManager()
}

// SwapAuthManager installs am as the package-level singleton for the
// duration of t and restores the previous singleton on cleanup. It
// returns am so callers can keep working with the installed instance.
func SwapAuthManager(t *testing.T, am *runner.AuthManager) *runner.AuthManager {
	t.Helper()
	prev := runner.SwapAuthManager(am)
	t.Cleanup(func() { runner.SwapAuthManager(prev) })
	return am
}
