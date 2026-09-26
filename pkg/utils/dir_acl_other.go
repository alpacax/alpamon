//go:build !windows

package utils

// SecureConfigDir is a no-op outside Windows: the packages and tmpfiles.d
// create the directories with root ownership and restrictive modes.
func SecureConfigDir() error { return nil }

// ConfigDirSecured is always true outside Windows.
func ConfigDirSecured() bool { return true }
