//go:build windows

package runner

// sessionID is meaningful only on Unix, where PAM and sudo exist. On Windows it
// always reports unknown so session resolution falls back to the parent-pid
// lookup.
func sessionID(pid int) (int, bool) { return 0, false }

// parentPID mirrors the Unix helper. auth.sock and its PAM producer do not
// exist on Windows, so the ancestor walk has nothing to resolve and always
// reports unknown.
func parentPID(pid int) (int, bool) { return 0, false }
