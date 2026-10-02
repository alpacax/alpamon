package runner

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// lookupSessionLocked resolves a sudo request to its tracked session, preferring
// the session ID (sid) and falling back to the parent pid. These tests pin that
// precedence, which is what lets sudo invoked inside a command—possibly after
// the shell execs sudo—still resolve to the originating session.

func TestLookupSessionLocked_PrefersSessionID(t *testing.T) {
	am := newTestAuthManager()
	sidSession := &SessionInfo{SessionID: "via-sid"}
	am.pidToSessionMap[1000] = sidSession

	got, ok := am.lookupSessionLocked(1000, true, 2000)
	require.True(t, ok, "expected sid lookup to win")
	require.Same(t, sidSession, got, "expected sid lookup to win")
}

func TestLookupSessionLocked_FallsBackToParentPID(t *testing.T) {
	am := newTestAuthManager()
	parentSession := &SessionInfo{SessionID: "via-ppid"}
	am.pidToSessionMap[2000] = parentSession

	// sid is known but not registered -> fall back to the parent pid.
	got, ok := am.lookupSessionLocked(9999, true, 2000)
	require.True(t, ok, "expected parent-pid fallback")
	require.Same(t, parentSession, got, "expected parent-pid fallback")
}

func TestLookupSessionLocked_SessionIDUnavailable_UsesParent(t *testing.T) {
	am := newTestAuthManager()
	parentSession := &SessionInfo{SessionID: "via-ppid"}
	am.pidToSessionMap[2000] = parentSession

	got, ok := am.lookupSessionLocked(0, false, 2000)
	require.True(t, ok, "expected parent-pid lookup when sid unavailable")
	require.Same(t, parentSession, got, "expected parent-pid lookup when sid unavailable")
}

func TestLookupSessionLocked_SessionIDWinsOverParent(t *testing.T) {
	am := newTestAuthManager()
	sidSession := &SessionInfo{SessionID: "via-sid"}
	parentSession := &SessionInfo{SessionID: "via-ppid"}
	am.pidToSessionMap[1000] = sidSession
	am.pidToSessionMap[2000] = parentSession

	got, ok := am.lookupSessionLocked(1000, true, 2000)
	require.True(t, ok, "expected sid to take precedence over parent pid")
	require.Same(t, sidSession, got, "expected sid to take precedence over parent pid")
}

func TestLookupSessionLocked_NoMatch(t *testing.T) {
	am := newTestAuthManager()
	got, ok := am.lookupSessionLocked(1, true, 2)
	require.False(t, ok, "expected no match on empty map, got %v", got)
}
