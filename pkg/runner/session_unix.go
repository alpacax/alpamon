//go:build !windows

package runner

import (
	"github.com/shirou/gopsutil/v4/process"
	"golang.org/x/sys/unix"
)

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

// parentPID returns the parent pid of pid. Reports ok=false when the process
// is gone or its parent cannot be read, which ends any ancestor walk rather
// than guessing. On Linux this is a single /proc/<pid>/stat read.
func parentPID(pid int) (int, bool) {
	if pid <= 1 {
		return 0, false
	}
	proc, err := process.NewProcess(int32(pid))
	if err != nil {
		return 0, false
	}
	ppid, err := proc.Ppid()
	if err != nil || ppid <= 0 {
		return 0, false
	}
	return int(ppid), true
}
