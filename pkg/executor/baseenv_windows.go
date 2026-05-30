//go:build windows

package executor

import (
	"os"
	"strings"
)

// processBaseEnv returns the base environment for a command. On Windows it
// inherits the parent process environment so PowerShell and other processes
// keep the Windows-specific variables they need (SystemRoot, PSModulePath,
// USERPROFILE, APPDATA, TEMP, ProgramData, etc.); missing these breaks process
// startup. Privilege demotion is a no-op on Windows, so there is no service-env
// leakage concern here. This mirrors the Websh path in pty_windows.go.
func processBaseEnv() map[string]string {
	env := make(map[string]string)
	for _, kv := range os.Environ() {
		if key, value, ok := strings.Cut(kv, "="); ok {
			env[key] = value
		}
	}
	return env
}
