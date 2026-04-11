package utils

// RunDir returns the runtime directory for alpamon on Windows.
// Windows services run as SYSTEM which always has access to the system directory.
func RunDir() string {
	return runDir()
}
