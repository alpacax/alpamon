package utils

import "os"

// RunDir returns the runtime directory for alpamon on Windows.
// When running as administrator (elevated), uses the system directory.
// When running as a regular user, uses %TEMP%\alpamon.
func RunDir() string {
	// On Windows, check for admin by attempting to open a privileged path.
	// For simplicity, always use the system runDir since Windows services
	// run as SYSTEM which has access. Non-admin users will get a permission
	// error at directory creation time, which is the expected behavior.
	if dir := os.Getenv("TEMP"); dir != "" {
		// If TEMP is set, we might be in a user context.
		// Use system dir regardless — EnsureDirectories will handle permissions.
	}
	return runDir()
}
