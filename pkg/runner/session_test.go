package runner

import "testing"

// lookupSessionLocked resolves a sudo request to its tracked session, preferring
// the session ID (sid) and falling back to the parent pid. These tests pin that
// precedence, which is what lets sudo invoked inside a command—possibly after
// the shell execs sudo—still resolve to the originating session.

func TestLookupSessionLocked_PrefersSessionID(t *testing.T) {
	am := newTestAuthManager()
	sidSession := &SessionInfo{SessionID: "via-sid"}
	am.pidToSessionMap[1000] = sidSession

	got, ok := am.lookupSessionLocked(1000, true, 2000)
	if !ok || got != sidSession {
		t.Fatalf("expected sid lookup to win, got %v ok=%v", got, ok)
	}
}

func TestLookupSessionLocked_FallsBackToParentPID(t *testing.T) {
	am := newTestAuthManager()
	parentSession := &SessionInfo{SessionID: "via-ppid"}
	am.pidToSessionMap[2000] = parentSession

	// sid is known but not registered -> fall back to the parent pid.
	got, ok := am.lookupSessionLocked(9999, true, 2000)
	if !ok || got != parentSession {
		t.Fatalf("expected parent-pid fallback, got %v ok=%v", got, ok)
	}
}

func TestLookupSessionLocked_SessionIDUnavailable_UsesParent(t *testing.T) {
	am := newTestAuthManager()
	parentSession := &SessionInfo{SessionID: "via-ppid"}
	am.pidToSessionMap[2000] = parentSession

	got, ok := am.lookupSessionLocked(0, false, 2000)
	if !ok || got != parentSession {
		t.Fatalf("expected parent-pid lookup when sid unavailable, got %v ok=%v", got, ok)
	}
}

func TestLookupSessionLocked_SessionIDWinsOverParent(t *testing.T) {
	am := newTestAuthManager()
	sidSession := &SessionInfo{SessionID: "via-sid"}
	parentSession := &SessionInfo{SessionID: "via-ppid"}
	am.pidToSessionMap[1000] = sidSession
	am.pidToSessionMap[2000] = parentSession

	got, ok := am.lookupSessionLocked(1000, true, 2000)
	if !ok || got != sidSession {
		t.Fatalf("expected sid to take precedence over parent pid, got %v ok=%v", got, ok)
	}
}

func TestLookupSessionLocked_NoMatch(t *testing.T) {
	am := newTestAuthManager()
	if got, ok := am.lookupSessionLocked(1, true, 2); ok {
		t.Fatalf("expected no match on empty map, got %v ok=%v", got, ok)
	}
}
