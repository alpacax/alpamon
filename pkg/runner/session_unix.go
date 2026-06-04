//go:build !windows

package runner

import "golang.org/x/sys/unix"

// sessionID returns the session ID (sid) of pid. Every process in the same
// session shares one sid—the session-leader pid—so sudo invoked anywhere inside
// a tracked Websh or command session resolves to the leader pid the tracker is
// keyed on, even when the shell execs sudo and they share a pid, or when
// intermediate processes sit between the shell and sudo. Reports ok=false when
// the sid cannot be determined; the caller then falls back to the parent pid.
func sessionID(pid int) (int, bool) {
	if pid <= 0 {
		return 0, false
	}
	sid, err := unix.Getsid(pid)
	if err != nil || sid <= 0 {
		return 0, false
	}
	return sid, true
}
