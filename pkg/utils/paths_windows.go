package utils

import "os"

var programData = os.Getenv("ProgramData")

// ConfigDir returns the configuration directory for alpamon on Windows.
func ConfigDir() string { return programData + `\alpamon` }

// DataDir returns the data directory for alpamon on Windows.
func DataDir() string { return programData + `\alpamon\data` }

// LogDir returns the log directory for alpamon on Windows.
func LogDir() string { return programData + `\alpamon\log` }

// runDir returns the system runtime directory for alpamon on Windows.
func runDir() string { return programData + `\alpamon\run` }

// DefaultShell returns the default shell for Windows.
func DefaultShell() string { return "powershell.exe" }

// DefaultShellArgs returns the default shell arguments for Windows.
func DefaultShellArgs() []string { return []string{"-NoLogo"} }

// DefaultPath returns the system PATH on Windows.
func DefaultPath() string { return os.Getenv("PATH") }

// EnvironmentFilePath returns empty on Windows (no /etc/environment equivalent).
func EnvironmentFilePath() string { return "" }
