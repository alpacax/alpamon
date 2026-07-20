package runner

// NewEmptyAuthManager returns an AuthManager populated just enough to
// exercise the PID tracker without starting the socket listener. It has
// no dependency on the testing package, so it is safe to keep in the
// shipped package; the actual test-only glue that swaps the singleton
// lives in the internal/runnertest package, which is firewalled by the
// Go compiler's internal rule and only imported from *_test.go files.
func NewEmptyAuthManager() *AuthManager {
	return &AuthManager{
		pidToSessionMap:    make(map[int]*SessionInfo),
		localSudoRequests:  make(map[string]*SudoRequest),
		completionChannels: make(map[string]chan struct{}),
		emitSem:            make(chan struct{}, emitConcurrencyLimit),
	}
}

// SwapAuthManager installs am as the package-level singleton and returns
// the previously installed one so callers can restore it. It is intended
// to be used from internal/runnertest (which adds *testing.T cleanup);
// direct use in production code is not supported.
func SwapAuthManager(am *AuthManager) *AuthManager {
	prev := authManager
	authManager = am
	return prev
}
