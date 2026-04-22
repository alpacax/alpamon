package runner

import "testing"

// NewAuthManagerForTest returns an AuthManager populated just enough to
// exercise the PID tracker. It does not start the socket listener.
//
// Exposed for tests in other packages (e.g. the shell handler) that need
// a real AuthManager singleton installed via SwapAuthManagerForTest.
func NewAuthManagerForTest() *AuthManager {
	return &AuthManager{
		pidToSessionMap:    make(map[int]*SessionInfo),
		localSudoRequests:  make(map[string]*SudoRequest),
		completionChannels: make(map[string]chan struct{}),
	}
}

// SwapAuthManagerForTest installs am as the package-level singleton for
// the duration of t and restores the previous singleton on cleanup.
// It returns am so callers can keep working with the installed instance.
func SwapAuthManagerForTest(t *testing.T, am *AuthManager) *AuthManager {
	t.Helper()
	prev := authManager
	authManager = am
	t.Cleanup(func() { authManager = prev })
	return am
}
