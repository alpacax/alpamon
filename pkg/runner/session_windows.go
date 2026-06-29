//go:build windows

package runner

// sessionID is meaningful only on Unix, where PAM and sudo exist. On Windows it
// always reports unknown so session resolution falls back to the parent-pid
// lookup.
func sessionID(pid int) (int, bool) { return 0, false }
