package utils

// ConfigDir returns the configuration directory for alpamon.
func ConfigDir() string { return "/etc/alpamon" }

// DataDir returns the data directory for alpamon.
func DataDir() string { return "/var/lib/alpamon" }

// LogDir returns the log directory for alpamon.
func LogDir() string { return "/var/log/alpamon" }

// runDir returns the system runtime directory for alpamon (used when running as root).
func runDir() string { return "/run/alpamon" }

// DefaultShell returns the default shell for the platform.
func DefaultShell() string { return "/bin/bash" }

// DefaultShellArgs returns the default shell arguments for interactive login.
func DefaultShellArgs() []string { return []string{"-il"} }

// DefaultPath returns the default PATH environment variable.
func DefaultPath() string {
	return "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
}

// EnvironmentFilePath returns the path to the system environment file.
func EnvironmentFilePath() string { return "/etc/environment" }
