package utils

// ConfigDir returns the configuration directory for alpamon.
func ConfigDir() string { return "/etc/alpamon" }

// DataDir returns the data directory for alpamon.
func DataDir() string { return "/var/lib/alpamon" }

// LogDir returns the log directory for alpamon.
func LogDir() string { return "/var/log/alpamon" }

// runDir returns the system runtime directory for alpamon (used when running as root).
func runDir() string { return "/var/run/alpamon" }

// DefaultShell returns the default shell for the platform.
// macOS defaults to zsh since Catalina.
func DefaultShell() string { return "/bin/zsh" }

// DefaultShellArgs returns the default shell arguments for interactive login.
func DefaultShellArgs() []string { return []string{"-il"} }

// DefaultPath returns the default PATH environment variable.
// Includes /opt/homebrew/bin for Apple Silicon Homebrew installations.
func DefaultPath() string {
	return "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/opt/homebrew/bin"
}

// EnvironmentFilePath returns the path to the system environment file.
// macOS does not use /etc/environment; returns empty to skip loading.
func EnvironmentFilePath() string { return "" }
