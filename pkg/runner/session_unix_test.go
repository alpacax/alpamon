//go:build !windows

package runner

import (
	"os"
	"testing"
)

func TestSessionID_CurrentProcess(t *testing.T) {
	sid, ok := sessionID(os.Getpid())
	if !ok || sid <= 0 {
		t.Fatalf("expected a valid sid for the current process, got sid=%d ok=%v", sid, ok)
	}
}

func TestSessionID_InvalidPID(t *testing.T) {
	// pid 0 would make getsid report the caller's (Alpamon's) own session; we
	// reject it up front so a bogus request can never match Alpamon's session.
	if _, ok := sessionID(0); ok {
		t.Error("expected ok=false for pid 0")
	}
	if _, ok := sessionID(-1); ok {
		t.Error("expected ok=false for negative pid")
	}
}
