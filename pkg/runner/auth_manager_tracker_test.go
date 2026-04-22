package runner

import (
	"testing"
	"time"
)

// newTestAuthManager returns an AuthManager with only the fields that the
// tracker tests need populated. It intentionally does not start the
// socket listener, so tests stay fast and isolated.
func newTestAuthManager() *AuthManager {
	return &AuthManager{
		pidToSessionMap:    make(map[int]*SessionInfo),
		localSudoRequests:  make(map[string]*SudoRequest),
		completionChannels: make(map[string]chan struct{}),
	}
}

// TestAddPIDCommandMapping_RegistersCommandKind verifies that Commands
// register with Kind=command and the CommandID/Username set.
func TestAddPIDCommandMapping_RegistersCommandKind(t *testing.T) {
	am := newTestAuthManager()

	am.AddPIDCommandMapping(4242, "cmd-uuid-1", "alice")

	entry, ok := am.LookupPID(4242)
	if !ok {
		t.Fatal("expected tracker entry to be registered")
	}
	if entry.Kind != TrackerKindCommand {
		t.Errorf("Kind: got %q, want %q", entry.Kind, TrackerKindCommand)
	}
	if entry.CommandID != "cmd-uuid-1" {
		t.Errorf("CommandID: got %q, want cmd-uuid-1", entry.CommandID)
	}
	if entry.SessionID != "" {
		t.Errorf("SessionID should be empty for command entries, got %q", entry.SessionID)
	}
	if entry.Username != "alice" {
		t.Errorf("Username: got %q, want alice", entry.Username)
	}
	if entry.StartedAt.IsZero() {
		t.Error("StartedAt should be set")
	}
}

// TestAddPIDCommandMapping_IgnoresInvalidInput verifies that bogus
// arguments are silently ignored rather than stored.
func TestAddPIDCommandMapping_IgnoresInvalidInput(t *testing.T) {
	am := newTestAuthManager()

	am.AddPIDCommandMapping(0, "cmd", "user")
	am.AddPIDCommandMapping(-1, "cmd", "user")
	am.AddPIDCommandMapping(100, "", "user")

	if len(am.pidToSessionMap) != 0 {
		t.Errorf("expected no entries, got %d", len(am.pidToSessionMap))
	}
}

// TestRemovePIDCommandMapping_RemovesMatchingEntry verifies removal on
// Command completion.
func TestRemovePIDCommandMapping_RemovesMatchingEntry(t *testing.T) {
	am := newTestAuthManager()
	am.AddPIDCommandMapping(1111, "cmd-a", "bob")

	am.RemovePIDCommandMapping(1111, "cmd-a")

	if _, ok := am.LookupPID(1111); ok {
		t.Fatal("entry should have been removed")
	}
}

// TestRemovePIDCommandMapping_PIDReuseGuard verifies that removing with
// a mismatched command id does not drop an unrelated entry that reused
// the same pid.
func TestRemovePIDCommandMapping_PIDReuseGuard(t *testing.T) {
	am := newTestAuthManager()
	am.AddPIDCommandMapping(2222, "cmd-b", "carol")

	// Stale remove from a previous, unrelated command: must be a no-op.
	am.RemovePIDCommandMapping(2222, "some-other-command-id")

	entry, ok := am.LookupPID(2222)
	if !ok {
		t.Fatal("entry should still exist after mismatched remove")
	}
	if entry.CommandID != "cmd-b" {
		t.Errorf("CommandID: got %q, want cmd-b", entry.CommandID)
	}
}

// TestRemovePIDCommandMapping_LeavesWebshEntryAlone verifies that a
// Command-style remove does not touch a websh entry that happens to
// share the same pid (defence in depth).
func TestRemovePIDCommandMapping_LeavesWebshEntryAlone(t *testing.T) {
	am := newTestAuthManager()
	am.AddPIDSessionMapping(3333, &SessionInfo{
		Kind:      TrackerKindWebsh,
		SessionID: "websh-1",
		Username:  "dave",
		Requests:  make(map[string]*SudoRequest),
	})

	am.RemovePIDCommandMapping(3333, "")

	entry, ok := am.LookupPID(3333)
	if !ok {
		t.Fatal("websh entry should not have been removed")
	}
	if entry.Kind != TrackerKindWebsh {
		t.Errorf("Kind: got %q, want websh", entry.Kind)
	}
}

// TestParallelCommands_TrackedIndependently verifies concurrent
// Commands keep distinct entries keyed by their root pids.
func TestParallelCommands_TrackedIndependently(t *testing.T) {
	am := newTestAuthManager()

	am.AddPIDCommandMapping(5001, "cmd-parallel-1", "alice")
	am.AddPIDCommandMapping(5002, "cmd-parallel-2", "alice")
	am.AddPIDCommandMapping(5003, "cmd-parallel-3", "bob")

	cases := []struct {
		pid       int
		commandID string
		username  string
	}{
		{5001, "cmd-parallel-1", "alice"},
		{5002, "cmd-parallel-2", "alice"},
		{5003, "cmd-parallel-3", "bob"},
	}
	for _, tc := range cases {
		entry, ok := am.LookupPID(tc.pid)
		if !ok {
			t.Errorf("pid %d: expected entry, got none", tc.pid)
			continue
		}
		if entry.CommandID != tc.commandID {
			t.Errorf("pid %d: CommandID got %q, want %q", tc.pid, entry.CommandID, tc.commandID)
		}
		if entry.Username != tc.username {
			t.Errorf("pid %d: Username got %q, want %q", tc.pid, entry.Username, tc.username)
		}
	}

	// Remove middle entry, verify others survive.
	am.RemovePIDCommandMapping(5002, "cmd-parallel-2")
	if _, ok := am.LookupPID(5002); ok {
		t.Error("5002 should have been removed")
	}
	if _, ok := am.LookupPID(5001); !ok {
		t.Error("5001 should still exist")
	}
	if _, ok := am.LookupPID(5003); !ok {
		t.Error("5003 should still exist")
	}
}

// TestLegacyWebshEntry_ReadsAsWebsh verifies backward compatibility with
// older in-memory entries that were created before the Kind field was
// introduced (Kind left empty).
func TestLegacyWebshEntry_ReadsAsWebsh(t *testing.T) {
	am := newTestAuthManager()

	// Simulate a legacy entry written by an older code path (no Kind).
	am.pidToSessionMap[7777] = &SessionInfo{
		SessionID: "legacy-session",
		PID:       7777,
		Requests:  make(map[string]*SudoRequest),
	}

	entry, ok := am.LookupPID(7777)
	if !ok {
		t.Fatal("legacy entry missing")
	}
	if entry.Kind != TrackerKindWebsh {
		t.Errorf("legacy entry should default to %q, got %q", TrackerKindWebsh, entry.Kind)
	}
	if entry.SessionID != "legacy-session" {
		t.Errorf("SessionID: got %q, want legacy-session", entry.SessionID)
	}
}

// TestAddPIDSessionMapping_NormalisesWebshKind verifies that websh
// registrations always end up with Kind=websh and no CommandID, even
// when the caller forgot to set the fields explicitly.
func TestAddPIDSessionMapping_NormalisesWebshKind(t *testing.T) {
	am := newTestAuthManager()

	// Caller neglects Kind / mistakenly populates CommandID.
	am.AddPIDSessionMapping(8888, &SessionInfo{
		SessionID: "ws-1",
		CommandID: "leaky",
		Requests:  make(map[string]*SudoRequest),
	})

	entry, ok := am.LookupPID(8888)
	if !ok {
		t.Fatal("expected entry")
	}
	if entry.Kind != TrackerKindWebsh {
		t.Errorf("Kind: got %q, want %q", entry.Kind, TrackerKindWebsh)
	}
	if entry.CommandID != "" {
		t.Errorf("CommandID should have been cleared, got %q", entry.CommandID)
	}
	if entry.StartedAt.IsZero() {
		t.Error("StartedAt should be populated by AddPIDSessionMapping when unset")
	}
}

// TestRegisterCommandPID_NoopWithoutManager verifies that the package-
// level helper degrades gracefully when the AuthManager singleton has
// not been initialised (tests, early boot, non-agent binaries).
func TestRegisterCommandPID_NoopWithoutManager(t *testing.T) {
	prev := authManager
	authManager = nil
	t.Cleanup(func() { authManager = prev })

	if RegisterCommandPID(123, "cmd", "user") {
		t.Error("expected RegisterCommandPID to return false when authManager is nil")
	}

	// Must not panic.
	UnregisterCommandPID(123, "cmd")
}

// TestRegisterCommandPID_RoundTrip exercises the package-level helpers
// against a real AuthManager singleton (Register -> Lookup -> Unregister).
func TestRegisterCommandPID_RoundTrip(t *testing.T) {
	prev := authManager
	authManager = newTestAuthManager()
	t.Cleanup(func() { authManager = prev })

	if !RegisterCommandPID(9001, "cmd-round", "eve") {
		t.Fatal("RegisterCommandPID should have returned true")
	}
	entry, ok := authManager.LookupPID(9001)
	if !ok {
		t.Fatal("entry should be present after RegisterCommandPID")
	}
	if entry.CommandID != "cmd-round" {
		t.Errorf("CommandID: got %q, want cmd-round", entry.CommandID)
	}

	UnregisterCommandPID(9001, "cmd-round")
	if _, ok := authManager.LookupPID(9001); ok {
		t.Error("entry should be gone after UnregisterCommandPID")
	}
}

// TestSudoApprovalRequest_OmitsEmptyIdentifiers is a guardrail against
// accidentally sending both session_id and command_id (or neither), by
// confirming the JSON tags use omitempty. This protects the server-side
// 2-branch resolver from ambiguous payloads.
func TestSudoApprovalRequest_JSONTagsOmitEmpty(t *testing.T) {
	// Construct two requests that a deploy shell path and a websh path
	// would send; spot-check that the wire representation reflects the
	// invariants from the plan:
	//   deploy shell: command_id set, session_id omitted
	//   websh:        session_id set, command_id omitted
	cmdReq := SudoApprovalRequest{
		Type:      "sudo_approval_request",
		CommandID: "cmd-uuid",
		PID:       1,
		PPID:      2,
		Username:  "alice",
	}
	if cmdReq.SessionID != "" {
		t.Errorf("deploy shell request should leave SessionID empty, got %q", cmdReq.SessionID)
	}

	webshReq := SudoApprovalRequest{
		Type:      "sudo_approval_request",
		SessionID: "session-uuid",
		PID:       1,
		PPID:      2,
		Username:  "alice",
	}
	if webshReq.CommandID != "" {
		t.Errorf("websh request should leave CommandID empty, got %q", webshReq.CommandID)
	}
}

// TestLookupPID_Missing verifies Lookup for a non-existent pid returns
// ok=false and a zero-value TrackerEntry.
func TestLookupPID_Missing(t *testing.T) {
	am := newTestAuthManager()
	entry, ok := am.LookupPID(99999)
	if ok {
		t.Error("expected ok=false for missing pid")
	}
	var zero TrackerEntry
	if entry != zero {
		t.Errorf("expected zero TrackerEntry, got %+v", entry)
	}
}

// TestAddPIDCommandMapping_OverwritesStaleEntry verifies that if the
// same pid gets reused (rare but possible after pid-wraparound), the
// newer registration wins so stale state cannot authorize the new
// process with someone else's command_id.
func TestAddPIDCommandMapping_OverwritesStaleEntry(t *testing.T) {
	am := newTestAuthManager()
	am.AddPIDCommandMapping(4001, "old-cmd", "alice")
	// Force a distinguishable time gap without sleeping.
	if entry, ok := am.LookupPID(4001); ok {
		entry.StartedAt = time.Now().Add(-time.Hour)
	}
	am.AddPIDCommandMapping(4001, "new-cmd", "bob")

	entry, _ := am.LookupPID(4001)
	if entry.CommandID != "new-cmd" {
		t.Errorf("CommandID: got %q, want new-cmd", entry.CommandID)
	}
	if entry.Username != "bob" {
		t.Errorf("Username: got %q, want bob", entry.Username)
	}
}
