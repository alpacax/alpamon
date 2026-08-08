package runner

import (
	"encoding/json"
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

// The shipped helper already builds exactly what these tests need.
func newTestAuthManager() *AuthManager {
	return NewEmptyAuthManager()
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

	// Even a well-formed Command-style remove with a concrete commandID
	// must not touch an entry that belongs to a different tracker kind.
	am.RemovePIDCommandMapping(3333, "cmd-bystander")

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

// TestAddPIDSessionMapping_CapturesProcessCreateTime verifies a live pid's
// OS creation time is captured at registration, which is what later lets a
// stale entry (its process gone, pid reused) be told apart from a live one.
func TestAddPIDSessionMapping_CapturesProcessCreateTime(t *testing.T) {
	am := newTestAuthManager()
	livePID := os.Getpid()

	am.AddPIDSessionMapping(livePID, &SessionInfo{
		SessionID: "sess-1",
		Requests:  make(map[string]*SudoRequest),
	})

	if am.pidToSessionMap[livePID].ProcessCreateTimeMs == 0 {
		t.Error("ProcessCreateTimeMs should be captured for a live pid")
	}
}

// TestAddPIDSessionMapping_LeavesCreateTimeUnsetForDeadPID verifies a pid
// with no live process leaves ProcessCreateTimeMs at zero rather than
// failing the registration, so lookups on this entry fall back to the
// pre-liveness-check trust-unconditionally behavior instead of erroring.
func TestAddPIDSessionMapping_LeavesCreateTimeUnsetForDeadPID(t *testing.T) {
	am := newTestAuthManager()
	const deadPID = 999999999 // outside any real pid range

	am.AddPIDSessionMapping(deadPID, &SessionInfo{
		SessionID: "sess-1",
		Requests:  make(map[string]*SudoRequest),
	})

	if got := am.pidToSessionMap[deadPID].ProcessCreateTimeMs; got != 0 {
		t.Errorf("ProcessCreateTimeMs: got %d, want 0 for a pid with no live process", got)
	}
}

// TestRegisterCommandPID_NoopWithoutManager verifies that the package-
// level helper degrades gracefully when the AuthManager singleton has
// not been initialised (tests, early boot, non-agent binaries).
func TestRegisterCommandPID_NoopWithoutManager(t *testing.T) {
	prev := authManager
	authManager = nil
	t.Cleanup(func() { authManager = prev })

	cleanup := RegisterCommandPID(123, "cmd", "user")
	if cleanup == nil {
		t.Error("RegisterCommandPID should always return a non-nil cleanup closure")
	}
	// Must not panic even when the AuthManager is absent.
	cleanup()
}

// TestRegisterCommandPID_RoundTrip exercises the package-level helper
// against a real AuthManager singleton (Register -> Lookup -> cleanup).
func TestRegisterCommandPID_RoundTrip(t *testing.T) {
	prev := authManager
	authManager = newTestAuthManager()
	t.Cleanup(func() { authManager = prev })

	cleanup := RegisterCommandPID(9001, "cmd-round", "eve")
	if cleanup == nil {
		t.Fatal("RegisterCommandPID returned a nil cleanup closure")
	}
	entry, ok := authManager.LookupPID(9001)
	if !ok {
		t.Fatal("entry should be present after RegisterCommandPID")
	}
	if entry.CommandID != "cmd-round" {
		t.Errorf("CommandID: got %q, want cmd-round", entry.CommandID)
	}

	cleanup()
	if _, ok := authManager.LookupPID(9001); ok {
		t.Error("entry should be gone after cleanup()")
	}
}

// TestSudoApprovalRequest_JSONTagsOmitEmpty is a guardrail against
// accidentally sending both session_id and command_id (or neither) on
// the wire. It marshals the struct and inspects the serialized keys so
// that a regression dropping `omitempty` from either field would be
// caught. This protects the server-side 2-branch resolver from
// ambiguous payloads.
func TestSudoApprovalRequest_JSONTagsOmitEmpty(t *testing.T) {
	// Deploy shell path: command_id set, session_id must be omitted.
	cmdReq := SudoApprovalRequest{
		Type:      "sudo_approval_request",
		CommandID: "cmd-uuid",
		PID:       1,
		PPID:      2,
		Username:  "alice",
	}
	cmdJSON, err := json.Marshal(cmdReq)
	if err != nil {
		t.Fatalf("marshal command request: %v", err)
	}
	if !strings.Contains(string(cmdJSON), `"command_id":"cmd-uuid"`) {
		t.Errorf("expected command_id in payload, got %s", cmdJSON)
	}
	if strings.Contains(string(cmdJSON), `"session_id"`) {
		t.Errorf("deploy shell payload must omit session_id, got %s", cmdJSON)
	}

	// Websh path: session_id set, command_id must be omitted.
	webshReq := SudoApprovalRequest{
		Type:      "sudo_approval_request",
		SessionID: "session-uuid",
		PID:       1,
		PPID:      2,
		Username:  "alice",
	}
	webshJSON, err := json.Marshal(webshReq)
	if err != nil {
		t.Fatalf("marshal websh request: %v", err)
	}
	if !strings.Contains(string(webshJSON), `"session_id":"session-uuid"`) {
		t.Errorf("expected session_id in payload, got %s", webshJSON)
	}
	if strings.Contains(string(webshJSON), `"command_id"`) {
		t.Errorf("websh payload must omit command_id, got %s", webshJSON)
	}

	// Neither-set path: both identifier keys must be absent, making the
	// payload unambiguous for the server's 2-branch resolver.
	emptyReq := SudoApprovalRequest{
		Type:     "sudo_approval_request",
		PID:      1,
		PPID:     2,
		Username: "alice",
	}
	emptyJSON, err := json.Marshal(emptyReq)
	if err != nil {
		t.Fatalf("marshal empty-id request: %v", err)
	}
	if strings.Contains(string(emptyJSON), `"session_id"`) ||
		strings.Contains(string(emptyJSON), `"command_id"`) {
		t.Errorf("payload with neither id must omit both keys, got %s", emptyJSON)
	}
}

// TestSudoApprovalResponse_ErrorCodePassthrough verifies that the optional
// error_code field round-trips through the response struct and stays off the
// wire when empty. alpacon-server emits error_code on denial; alpamon
// unmarshals the server control message into SudoApprovalResponse and
// re-marshals it onto the auth socket, so the field must survive that hop. The
// omitempty guard keeps older servers (which never send error_code) wire-
// compatible with socket clients that predate the field.
func TestSudoApprovalResponse_ErrorCodePassthrough(t *testing.T) {
	// Server sends error_code on denial: it must survive unmarshal→marshal.
	serverMsg := `{"type":"sudo_approval_response","request_id":"r1","approved":false,"reason":"sudo_no_worksession_policy","error_code":"SUDO_NO_WORKSESSION_POLICY"}`
	var resp SudoApprovalResponse
	if err := json.Unmarshal([]byte(serverMsg), &resp); err != nil {
		t.Fatalf("unmarshal server message: %v", err)
	}
	if resp.ErrorCode != "SUDO_NO_WORKSESSION_POLICY" {
		t.Errorf("expected error_code to be parsed, got %q", resp.ErrorCode)
	}
	out, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal response: %v", err)
	}
	if !strings.Contains(string(out), `"error_code":"SUDO_NO_WORKSESSION_POLICY"`) {
		t.Errorf("expected error_code in re-marshaled payload, got %s", out)
	}

	// Backward compat: a server that omits error_code (or an approval) must not
	// introduce the key on the wire, so clients predating the field are
	// unaffected.
	approved := SudoApprovalResponse{Type: "sudo_approval_response", RequestID: "r2", Approved: true}
	approvedJSON, err := json.Marshal(approved)
	if err != nil {
		t.Fatalf("marshal approved response: %v", err)
	}
	if strings.Contains(string(approvedJSON), `"error_code"`) {
		t.Errorf("empty error_code must be omitted from payload, got %s", approvedJSON)
	}

	// Older server omits error_code entirely: it must unmarshal to "".
	var legacy SudoApprovalResponse
	legacyMsg := `{"type":"sudo_approval_response","request_id":"r3","approved":false,"reason":"denied"}`
	if err := json.Unmarshal([]byte(legacyMsg), &legacy); err != nil {
		t.Fatalf("unmarshal legacy message: %v", err)
	}
	if legacy.ErrorCode != "" {
		t.Errorf("absent error_code must unmarshal to empty, got %q", legacy.ErrorCode)
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

// sendAndAwaitAuthSocketResponse drives a raw auth.sock request through
// handleSudoRequest (which does its own socket read before dispatching) and
// returns the raw response bytes written back.
func sendAndAwaitAuthSocketResponse(t *testing.T, am *AuthManager, raw []byte) []byte {
	t.Helper()
	server, client := net.Pipe()
	go am.handleSudoRequest(server)

	if _, err := client.Write(raw); err != nil {
		t.Fatalf("failed to write request: %v", err)
	}
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 4096)
	n, err := client.Read(buf)
	if err != nil {
		t.Fatalf("failed to read response: %v", err)
	}
	return buf[:n]
}

// TestHandleSudoRequest_CheckUser_ReusedPIDNotTrusted verifies that the
// check_user path no longer reports is_alpacon_user=true through a
// pidToSessionMap entry whose pid has been reused by an unrelated process,
// and that the stale entry is evicted.
func TestHandleSudoRequest_CheckUser_ReusedPIDNotTrusted(t *testing.T) {
	am := newTestAuthManager()
	leaderPID := os.Getpid()
	am.AddPIDSessionMapping(leaderPID, &SessionInfo{
		SessionID: "sess-1",
		Requests:  make(map[string]*SudoRequest),
	})
	if am.pidToSessionMap[leaderPID].ProcessCreateTimeMs == 0 {
		t.Fatal("test process is alive; ProcessCreateTimeMs must have been captured")
	}
	// Simulate leaderPID having been reused by an unrelated process.
	am.pidToSessionMap[leaderPID].ProcessCreateTimeMs = 1

	raw, err := json.Marshal(IsAlpconRequest{
		Type: "check_user", Username: "mallory", Groupname: "mallory",
		PID: 900002, PPID: leaderPID,
	})
	if err != nil {
		t.Fatalf("failed to marshal request: %v", err)
	}

	respRaw := sendAndAwaitAuthSocketResponse(t, am, raw)
	var resp IsAlpconResponse
	if err := json.Unmarshal(respRaw, &resp); err != nil {
		t.Fatalf("invalid response JSON %q: %v", respRaw, err)
	}
	if resp.IsAlpconUser {
		t.Error("a stale entry (pid reused) must not report is_alpacon_user=true")
	}
	if _, exists := am.pidToSessionMap[leaderPID]; exists {
		t.Error("the stale entry must be evicted once detected")
	}
}

// TestHandleSudoApprovalRequest_ReusedPIDFallsBackToLocalPolicy verifies
// that a sudo_approval request whose ppid resolves to a stale
// pidToSessionMap entry (pid reused) is treated as local sudo and evaluated
// against blockLocalSudo, rather than silently granted Alpacon-approved
// status through the leaked entry.
func TestHandleSudoApprovalRequest_ReusedPIDFallsBackToLocalPolicy(t *testing.T) {
	for _, tc := range []struct {
		name           string
		blockLocalSudo bool
		wantApproved   bool
		wantReason     string
	}{
		{name: "block_local_sudo=false allows it", blockLocalSudo: false, wantApproved: true, wantReason: "Approved"},
		{name: "block_local_sudo=true rejects it", blockLocalSudo: true, wantApproved: false, wantReason: "No Authority"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			am := newTestAuthManager()
			am.blockLocalSudo = tc.blockLocalSudo
			leaderPID := os.Getpid()
			am.AddPIDSessionMapping(leaderPID, &SessionInfo{
				SessionID: "sess-1",
				Requests:  make(map[string]*SudoRequest),
			})
			am.pidToSessionMap[leaderPID].ProcessCreateTimeMs = 1 // simulate a reused pid

			raw, err := json.Marshal(SudoApprovalRequest{
				Type: "sudo_approval", RequestID: "req-1", Username: "mallory",
				Groupname: "mallory", PID: 900003, PPID: leaderPID, Command: "id",
			})
			if err != nil {
				t.Fatalf("failed to marshal request: %v", err)
			}

			respRaw := sendAndAwaitAuthSocketResponse(t, am, raw)
			var resp SudoApprovalResponse
			if err := json.Unmarshal(respRaw, &resp); err != nil {
				t.Fatalf("invalid response JSON %q: %v", respRaw, err)
			}
			if resp.IsAlpconUser {
				t.Error("a stale entry (pid reused) must not report is_alpacon_user=true")
			}
			if resp.Approved != tc.wantApproved || resp.Reason != tc.wantReason {
				t.Errorf("Approved/Reason: got %v/%q, want %v/%q", resp.Approved, resp.Reason, tc.wantApproved, tc.wantReason)
			}
			if _, exists := am.pidToSessionMap[leaderPID]; exists {
				t.Error("the stale entry must be evicted once detected")
			}
		})
	}
}

// TestHandleSudoApprovalRequest_RemovedSessionFallsBackToLocalPolicy
// verifies that a sudo_approval request arriving after its session's entry
// has already been removed (normal session close, or any other path that
// leaves pidToSessionMap without a match) falls back to local sudo policy
// end-to-end through handleSudoRequest, rather than erroring or hanging.
// The lock-scoped re-validation added alongside the liveness check
// (am.pidToSessionMap[session.PID] != session, guarding the narrower window
// between an unlocked verify and the write-lock re-acquisition) shares this
// same fallback path; its pointer-identity safety is covered directly by
// TestSessionStillLive_DoesNotEvictReplacedEntry.
func TestHandleSudoApprovalRequest_RemovedSessionFallsBackToLocalPolicy(t *testing.T) {
	am := newTestAuthManager()
	leaderPID := os.Getpid()
	session := &SessionInfo{SessionID: "sess-1", Requests: make(map[string]*SudoRequest)}
	am.AddPIDSessionMapping(leaderPID, session)
	// Remove it right away to simulate the session having already closed
	// normally by the time this sudo_approval request arrives.
	am.RemovePIDSessionMapping(leaderPID)

	raw, err := json.Marshal(SudoApprovalRequest{
		Type: "sudo_approval", RequestID: "req-2", Username: "alice",
		Groupname: "alice", PID: 900004, PPID: leaderPID, Command: "id",
	})
	if err != nil {
		t.Fatalf("failed to marshal request: %v", err)
	}

	respRaw := sendAndAwaitAuthSocketResponse(t, am, raw)
	var resp SudoApprovalResponse
	if err := json.Unmarshal(respRaw, &resp); err != nil {
		t.Fatalf("invalid response JSON %q: %v", respRaw, err)
	}
	if resp.IsAlpconUser {
		t.Error("a removed entry must not report is_alpacon_user=true")
	}
	if !resp.Approved || resp.Reason != "Approved" {
		t.Errorf("expected local sudo approval (block_local_sudo defaults to false), got %+v", resp)
	}
}
