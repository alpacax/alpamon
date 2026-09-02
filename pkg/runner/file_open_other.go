//go:build windows

package runner

import "os"

// openEntrypoint is unreachable on Windows: the lane declines with
// FILE_EXEC_UNSUPPORTED before a path is ever opened. It exists so the
// cross-platform file compiles, and it is deliberately the plain open rather
// than a panic — a build that somehow reached it should fail closed later on
// the missing sealed object, not crash the agent.
func openEntrypoint(path string) (*os.File, error) {
	return os.Open(path)
}
