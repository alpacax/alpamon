package runner

import (
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestAuthManager() *AuthManager {
	am := NewEmptyAuthManager()
	am.peerCreds = trustedTestPeer
	return am
}

// trustedTestPeer stands in for the kernel check on net.Pipe connections; it skips
// the pid check so payloads without a matching pid still reach their handler.
func trustedTestPeer(net.Conn) (peerCred, error) {
	return peerCred{uid: os.Geteuid(), skipPIDCheck: true}, nil
}

// TestAddPIDCommandMapping_RegistersCommandKind verifies that Commands
// register with Kind=command and the CommandID/Username set.
func TestAddPIDCommandMapping_RegistersCommandKind(t *testing.T) {
	am := newTestAuthManager()

	am.AddPIDCommandMapping(4242, "cmd-uuid-1", "alice")

	entry, ok := am.LookupPID(4242)
	require.True(t, ok, "expected tracker entry to be registered")
	assert.Equal(t, TrackerKindCommand, entry.Kind)
	assert.Equal(t, "cmd-uuid-1", entry.CommandID)
	assert.Empty(t, entry.SessionID, "SessionID should be empty for command entries")
	assert.Equal(t, "alice", entry.Username)
	assert.False(t, entry.StartedAt.IsZero(), "StartedAt should be set")
}

// TestAddPIDCommandMapping_IgnoresInvalidInput verifies that bogus
// arguments are silently ignored rather than stored.
func TestAddPIDCommandMapping_IgnoresInvalidInput(t *testing.T) {
	am := newTestAuthManager()

	am.AddPIDCommandMapping(0, "cmd", "user")
	am.AddPIDCommandMapping(-1, "cmd", "user")
	am.AddPIDCommandMapping(100, "", "user")

	assert.Empty(t, am.pidToSessionMap, "expected no entries")
}

// TestRemovePIDCommandMapping_RemovesMatchingEntry verifies removal on
// Command completion.
func TestRemovePIDCommandMapping_RemovesMatchingEntry(t *testing.T) {
	am := newTestAuthManager()
	am.AddPIDCommandMapping(1111, "cmd-a", "bob")

	am.RemovePIDCommandMapping(1111, "cmd-a")

	_, ok := am.LookupPID(1111)
	assert.False(t, ok, "entry should have been removed")
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
	require.True(t, ok, "entry should still exist after mismatched remove")
	assert.Equal(t, "cmd-b", entry.CommandID)
}

// TestRemovePIDCommandMapping_LeavesWebshEntryAlone verifies that a
// Command-style remove does not touch a Websh entry that happens to
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
	require.True(t, ok, "Websh entry should not have been removed")
	assert.Equal(t, TrackerKindWebsh, entry.Kind)
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
		if !assert.True(t, ok, "pid %d: expected entry, got none", tc.pid) {
			continue
		}
		assert.Equal(t, tc.commandID, entry.CommandID, "pid %d: CommandID", tc.pid)
		assert.Equal(t, tc.username, entry.Username, "pid %d: Username", tc.pid)
	}

	// Remove middle entry, verify others survive.
	am.RemovePIDCommandMapping(5002, "cmd-parallel-2")
	_, ok := am.LookupPID(5002)
	assert.False(t, ok, "5002 should have been removed")
	_, ok = am.LookupPID(5001)
	assert.True(t, ok, "5001 should still exist")
	_, ok = am.LookupPID(5003)
	assert.True(t, ok, "5003 should still exist")
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
	require.True(t, ok, "legacy entry missing")
	assert.Equal(t, TrackerKindWebsh, entry.Kind, "legacy entry should default to the Websh kind")
	assert.Equal(t, "legacy-session", entry.SessionID)
}

// TestAddPIDSessionMapping_NormalisesWebshKind verifies that Websh
// registrations always end up with Kind == TrackerKindWebsh and no
// CommandID, even when the caller forgot to set the fields explicitly.
func TestAddPIDSessionMapping_NormalisesWebshKind(t *testing.T) {
	am := newTestAuthManager()

	// Caller neglects Kind / mistakenly populates CommandID.
	am.AddPIDSessionMapping(8888, &SessionInfo{
		SessionID: "ws-1",
		CommandID: "leaky",
		Requests:  make(map[string]*SudoRequest),
	})

	entry, ok := am.LookupPID(8888)
	require.True(t, ok, "expected entry")
	assert.Equal(t, TrackerKindWebsh, entry.Kind)
	assert.Empty(t, entry.CommandID, "CommandID should have been cleared")
	assert.False(t, entry.StartedAt.IsZero(), "StartedAt should be populated by AddPIDSessionMapping when unset")
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
	require.NoError(t, err, "marshal command request")
	assert.Contains(t, string(cmdJSON), `"command_id":"cmd-uuid"`)
	assert.NotContains(t, string(cmdJSON), `"session_id"`, "deploy shell payload must omit session_id")

	// Websh path: session_id set, command_id must be omitted.
	webshReq := SudoApprovalRequest{
		Type:      "sudo_approval_request",
		SessionID: "session-uuid",
		PID:       1,
		PPID:      2,
		Username:  "alice",
	}
	webshJSON, err := json.Marshal(webshReq)
	require.NoError(t, err, "marshal Websh request")
	assert.Contains(t, string(webshJSON), `"session_id":"session-uuid"`)
	assert.NotContains(t, string(webshJSON), `"command_id"`, "Websh payload must omit command_id")

	// Neither-set path: both identifier keys must be absent, making the
	// payload unambiguous for the server's 2-branch resolver.
	emptyReq := SudoApprovalRequest{
		Type:     "sudo_approval_request",
		PID:      1,
		PPID:     2,
		Username: "alice",
	}
	emptyJSON, err := json.Marshal(emptyReq)
	require.NoError(t, err, "marshal empty-id request")
	assert.NotContains(t, string(emptyJSON), `"session_id"`, "payload with neither id must omit both keys")
	assert.NotContains(t, string(emptyJSON), `"command_id"`, "payload with neither id must omit both keys")
}

// TestSudoApprovalRequest_RunasUserPassthrough verifies that the optional
// runas_user field sent by the approval plugin survives the socket unmarshal
// and the re-marshal for the server, and stays off the wire when absent.
func TestSudoApprovalRequest_RunasUserPassthrough(t *testing.T) {
	pluginMsg := `{"type":"sudo_approval","username":"alice","groupname":"alice","pid":10,"ppid":9,"command":"ls","is_alpacon_user":null,"session_id":"","request_id":"10","runas_user":"deploy"}`
	var req SudoApprovalRequest
	require.NoError(t, json.Unmarshal([]byte(pluginMsg), &req))
	assert.Equal(t, "deploy", req.RunasUser)

	out, err := json.Marshal(req)
	require.NoError(t, err)
	assert.Contains(t, string(out), `"runas_user":"deploy"`)

	var uidReq SudoApprovalRequest
	require.NoError(t, json.Unmarshal([]byte(`{"type":"sudo_approval","request_id":"11","runas_user":"#1234"}`), &uidReq))
	assert.Equal(t, "#1234", uidReq.RunasUser)

	// An older plugin (or the PAM-only path) omits the field; it must stay
	// absent on the way to the server.
	var legacy SudoApprovalRequest
	require.NoError(t, json.Unmarshal([]byte(`{"type":"sudo_approval","username":"alice","pid":10,"ppid":9,"command":"ls","request_id":"12"}`), &legacy))
	assert.Empty(t, legacy.RunasUser)
	legacyOut, err := json.Marshal(legacy)
	require.NoError(t, err)
	assert.NotContains(t, string(legacyOut), `"runas_user"`)
}

// TestSudoApprovalResponse_ErrorCodePassthrough verifies that the optional
// error_code field round-trips through the response struct and stays off the
// wire when empty. alpacon-server emits error_code on denial; Alpamon
// unmarshals the server control message into SudoApprovalResponse and
// re-marshals it onto the auth socket, so the field must survive that hop. The
// omitempty guard keeps older servers (which never send error_code) wire-
// compatible with socket clients that predate the field.
func TestSudoApprovalResponse_ErrorCodePassthrough(t *testing.T) {
	// Server sends error_code on denial: it must survive unmarshal→marshal.
	serverMsg := `{"type":"sudo_approval_response","request_id":"r1","approved":false,"reason":"sudo_no_worksession_policy","error_code":"SUDO_NO_WORKSESSION_POLICY"}`
	var resp SudoApprovalResponse
	require.NoError(t, json.Unmarshal([]byte(serverMsg), &resp), "unmarshal server message")
	assert.Equal(t, "SUDO_NO_WORKSESSION_POLICY", resp.ErrorCode, "expected error_code to be parsed")
	out, err := json.Marshal(resp)
	require.NoError(t, err, "marshal response")
	assert.Contains(t, string(out), `"error_code":"SUDO_NO_WORKSESSION_POLICY"`)

	// Backward compat: a server that omits error_code (or an approval) must not
	// introduce the key on the wire, so clients predating the field are
	// unaffected.
	approved := SudoApprovalResponse{Type: "sudo_approval_response", RequestID: "r2", Approved: true}
	approvedJSON, err := json.Marshal(approved)
	require.NoError(t, err, "marshal approved response")
	assert.NotContains(t, string(approvedJSON), `"error_code"`, "empty error_code must be omitted from payload")

	// Older server omits error_code entirely: it must unmarshal to "".
	var legacy SudoApprovalResponse
	legacyMsg := `{"type":"sudo_approval_response","request_id":"r3","approved":false,"reason":"denied"}`
	require.NoError(t, json.Unmarshal([]byte(legacyMsg), &legacy), "unmarshal legacy message")
	assert.Empty(t, legacy.ErrorCode, "absent error_code must unmarshal to empty")
}

// TestLookupPID_Missing verifies Lookup for a non-existent pid returns
// ok=false and a zero-value TrackerEntry.
func TestLookupPID_Missing(t *testing.T) {
	am := newTestAuthManager()
	entry, ok := am.LookupPID(99999)
	assert.False(t, ok, "expected ok=false for missing pid")
	assert.Equal(t, TrackerEntry{}, entry, "expected zero TrackerEntry")
}

// TestAddPIDCommandMapping_OverwritesStaleEntry verifies that if the
// same pid gets reused (rare but possible after pid-wraparound), the
// newer registration wins so stale state cannot authorize the new
// process with someone else's command_id.
func TestAddPIDCommandMapping_OverwritesStaleEntry(t *testing.T) {
	am := newTestAuthManager()
	am.AddPIDCommandMapping(4001, "old-cmd", "alice")
	am.AddPIDCommandMapping(4001, "new-cmd", "bob")

	entry, ok := am.LookupPID(4001)
	require.True(t, ok, "entry should survive the overwrite")
	assert.Equal(t, "new-cmd", entry.CommandID)
	assert.Equal(t, "bob", entry.Username)
}

func TestSudoApprovalResponse_ApprovalDetailsPassthrough(t *testing.T) {
	for _, tc := range []struct{ name, fields, hint, request string }{
		{name: "with details", fields: `,"hint":"Run the approval command\nthen retry","approval_request":"request-123"`, hint: "Run the approval command\nthen retry", request: "request-123"},
		{name: "hint only", fields: `,"hint":"Retry after approval"`, hint: "Retry after approval"},
		{name: "request only", fields: `,"approval_request":"request-456"`, request: "request-456"},
		{name: "absent"},
		{name: "empty", fields: `,"hint":"","approval_request":""`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var response SudoApprovalResponse
			require.NoError(t, json.Unmarshal([]byte(`{"type":"sudo_approval_response","request_id":"r1","approved":false,"reason":"Approval required","unknown":"ignored"`+tc.fields+`}`), &response))
			assert.Equal(t, tc.hint, response.Hint)
			assert.Equal(t, tc.request, response.ApprovalRequest)
			client, conn := net.Pipe()
			defer func() { require.NoError(t, client.Close()) }()
			result := make(chan error, 1)
			request := newSudoRequest(conn, SudoApprovalRequest{RequestID: "r1"})
			go func() { result <- newTestAuthManager().deliverVerdict(request, response) }()
			var frame map[string]any
			require.NoError(t, json.NewDecoder(client).Decode(&frame))
			require.NoError(t, <-result)
			assert.Equal(t, "Approval required", frame["reason"])
			for key, value := range map[string]string{"hint": tc.hint, "approval_request": tc.request} {
				if value == "" {
					assert.NotContains(t, frame, key)
				} else {
					assert.Equal(t, value, frame[key])
				}
			}
			assert.NotContains(t, frame, "unknown")
		})
	}
}

func TestUnattributedSudoForTrackedUsername(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		am := newTestAuthManager()
		am.AddPIDCommandMapping(2147483645, "command-id", "alice")
		am.UpdateBlockLocalSudo(false)
		req := SudoApprovalRequest{
			Type: "check_user", Username: "alice",
			PID: 2147483647, PPID: 2147483646, RequestID: "2147483647",
		}
		client, _ := startPAMClient(t, am, req)
		var classification map[string]any
		require.NoError(t, json.Unmarshal([]byte(client.output(t)), &classification))
		assert.Equal(t, "is_alpacon_response", classification["type"])
		assert.Equal(t, false, classification["is_alpacon_user"])
		assert.Equal(t, true, classification["unmatched_session"])

		req.Type = "sudo_approval"
		client, _ = startPAMClient(t, am, req)
		var verdict SudoApprovalResponse
		require.NoError(t, json.Unmarshal([]byte(client.output(t)), &verdict))
		assert.Equal(t, "sudo_approval_response", verdict.Type)
		assert.Equal(t, req.RequestID, verdict.RequestID)
		assert.False(t, verdict.Approved)
		assert.Empty(t, verdict.CommandID)
		assert.Empty(t, verdict.SessionID)
	})
}

func TestSudoSessionIdentity(t *testing.T) {
	command := &SessionInfo{Kind: TrackerKindCommand, Username: "managed", uid: "4100", groupPath: "/agent/alpamon-command-one"}
	websh := &SessionInfo{Kind: TrackerKindWebsh, uid: "4200"}
	am := AuthManager{pidToSessionMap: map[int]*SessionInfo{70: command, 80: websh}}
	for _, tc := range []struct {
		name    string
		id      sudoIdentity
		want    *SessionInfo
		managed bool
	}{
		{"command subgroup", sudoIdentity{group: command.groupPath + "/worker", commandGroup: true}, command, true},
		{"different group with tracked parent", sudoIdentity{parent: 70, group: "/local", uid: "4100"}, nil, true},
		{"retired command group", sudoIdentity{group: "/agent/alpamon-command-ended", commandGroup: true}, nil, false},
		{"ancestor fallback", sudoIdentity{ancestors: []int{90, 80}}, websh, true},
		{"unmatched account alias", sudoIdentity{username: "alias", uid: "4100"}, nil, true},
		{"unmatched process uid", sudoIdentity{processUID: "4100"}, nil, true},
		{"local account", sudoIdentity{uid: "4300"}, nil, false},
		{"managed process with root claim", sudoIdentity{processUID: "4100", username: "root", uid: "0"}, nil, true},
		{"local process with managed claim", sudoIdentity{processUID: "4300", username: "managed", uid: "4100"}, nil, false},
		{"root process with managed claim", sudoIdentity{processUID: "0", username: "managed", uid: "4100"}, nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			session, managed := am.sudoSessionLocked(tc.id)
			assert.Same(t, tc.want, session)
			assert.Equal(t, tc.managed, managed)
		})
	}
}

func TestLocalSudoApproval(t *testing.T) {
	for _, username := range []string{"root", "local-user"} {
		t.Run(username, func(t *testing.T) {
			if username == "root" && accountUID(username) != "0" {
				t.Skip("requires a root account with UID 0")
			}
			synctest.Test(t, func(t *testing.T) {
				am := newTestAuthManager()
				am.AddPIDCommandMapping(2147483645, "command-id", "root")
				am.UpdateBlockLocalSudo(false)
				req := SudoApprovalRequest{Type: "check_user", Username: username, PID: 2147483647, PPID: 2147483646, RequestID: "2147483647"}
				client, _ := startPAMClient(t, am, req)
				var classification IsAlpconResponse
				require.NoError(t, json.Unmarshal([]byte(client.output(t)), &classification))
				assert.False(t, classification.IsAlpconUser)
				assert.Equal(t, username == "root", classification.UnmatchedSession)
				req.Type = "sudo_approval"
				client, _ = startPAMClient(t, am, req)
				var response SudoApprovalResponse
				require.NoError(t, json.Unmarshal([]byte(client.output(t)), &response))
				assert.Equal(t, username != "root", response.Approved)
			})
		})
	}
}

func TestClassificationWaitsForPIDRegistration(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("requires Unix process ancestry")
	}
	cmd := exec.CommandContext(t.Context(), "/bin/cat")
	input, err := cmd.StdinPipe()
	require.NoError(t, err)
	require.NoError(t, cmd.Start())
	defer func() {
		assert.NoError(t, input.Close())
		assert.NoError(t, cmd.Wait())
	}()

	synctest.Test(t, func(t *testing.T) {
		am := newTestAuthManager()
		finishUnrelated := am.beginCommandStart("bob", "4200", "")
		defer finishUnrelated()
		finish := am.beginCommandStart("alice", strconv.Itoa(os.Getuid()), "")
		req := SudoApprovalRequest{Type: "check_user", Username: "alice", PID: os.Getpid(), PPID: cmd.Process.Pid}
		client, _ := startPAMClient(t, am, req)
		synctest.Wait()
		select {
		case <-client.done:
			finish()
			t.Fatal("classification completed before registration")
		default:
		}
		am.addPIDCommandMapping(req.PPID, "command", "alice", "")
		finish()
		var response IsAlpconResponse
		require.NoError(t, json.Unmarshal([]byte(client.output(t)), &response))
		assert.True(t, response.IsAlpconUser)
		assert.False(t, response.UnmatchedSession)
		session, _ := am.sudoSessionLocked(sudoIdentity{sid: req.PPID, sidOK: true})
		require.NotNil(t, session)
		assert.Empty(t, session.groupPath)
		assert.Equal(t, "command", session.CommandID)
	})
}

func TestDirectorySessionDeniesUnmatchedSudo(t *testing.T) {
	if (runtime.GOOS != "linux" && runtime.GOOS != "darwin") || os.Getuid() == 0 {
		t.Skip("requires kernel non-root UID")
	}
	const account = "alpamon-test-directory-only"
	require.Empty(t, accountUID(account))
	cmd := exec.CommandContext(t.Context(), "/bin/cat")
	input, err := cmd.StdinPipe()
	require.NoError(t, err)
	require.NoError(t, cmd.Start())
	defer func() {
		assert.NoError(t, input.Close())
		assert.NoError(t, cmd.Wait())
	}()
	for _, kind := range []string{TrackerKindCommand, TrackerKindWebsh} {
		t.Run(kind, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				am := newTestAuthManager()
				if kind == TrackerKindCommand {
					am.AddPIDCommandMapping(cmd.Process.Pid, "command", account)
				} else {
					am.AddPIDSessionMapping(cmd.Process.Pid, &SessionInfo{Username: account})
				}
				am.UpdateBlockLocalSudo(false)
				req := SudoApprovalRequest{Type: "sudo_approval", Username: account, PID: os.Getpid(), RequestID: strconv.Itoa(os.Getpid())}
				client, _ := startPAMClient(t, am, req)
				var response SudoApprovalResponse
				require.NoError(t, json.Unmarshal([]byte(client.output(t)), &response))
				assert.False(t, response.Approved)
			})
		})
	}
}

func TestRegisteredSessionDuringAnotherStart(t *testing.T) {
	for _, typ := range []string{"check_user", "sudo_approval"} {
		t.Run(typ, func(t *testing.T) {
			am := newTestAuthManager()
			// An unknown kind returns a local approval verdict without contacting a server.
			const parent = 2147483646
			am.AddPIDSessionMapping(parent, &SessionInfo{Kind: "unknown"})
			finish := am.beginCommandStart("alice", "", "")
			defer finish()
			req := SudoApprovalRequest{Type: typ, PID: os.Getpid(), PPID: parent, RequestID: strconv.Itoa(os.Getpid())}
			client, _ := startPAMClient(t, am, req)
			select {
			case <-client.done:
				if typ == "check_user" {
					var response IsAlpconResponse
					require.NoError(t, json.Unmarshal(client.got.Bytes(), &response))
					assert.True(t, response.IsAlpconUser)
				} else {
					var response SudoApprovalResponse
					require.NoError(t, json.Unmarshal(client.got.Bytes(), &response))
					assert.Equal(t, "Unknown session kind", response.Reason)
				}
			case <-time.After(time.Second):
				t.Fatal("registered session waited for unrelated start")
			}
		})
	}
}

func TestUnrelatedLocalSudoDuringCommandStart(t *testing.T) {
	for _, typ := range []string{"check_user", "sudo_approval"} {
		t.Run(typ, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				am := newTestAuthManager()
				am.UpdateBlockLocalSudo(false)
				finish := am.beginCommandStart("alice", strconv.Itoa(os.Getuid()+1), "")
				defer finish()
				req := SudoApprovalRequest{Type: typ, Username: "local-user", PID: os.Getpid(), RequestID: strconv.Itoa(os.Getpid())}
				client, _ := startPAMClient(t, am, req)
				output := []byte(client.output(t))
				if typ == "check_user" {
					var response IsAlpconResponse
					require.NoError(t, json.Unmarshal(output, &response))
					assert.False(t, response.IsAlpconUser)
					assert.False(t, response.UnmatchedSession)
				} else {
					var response SudoApprovalResponse
					require.NoError(t, json.Unmarshal(output, &response))
					assert.True(t, response.Approved)
				}
			})
		})
	}
}

func TestSudoLookupWaitsForRelevantCommandStart(t *testing.T) {
	const group = "/agent/alpamon-command-test"
	for _, tc := range []struct {
		name        string
		id          sudoIdentity
		wantSession bool
	}{
		{"cgroup", sudoIdentity{group: group + "/child", commandGroup: true}, true},
		{"cgroup with different UID", sudoIdentity{group: group + "/child", commandGroup: true, processUID: "4300"}, true},
		{"managed UID", sudoIdentity{processUID: "4100"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				am := newTestAuthManager()
				finishUnrelated := am.beginCommandStart("bob", "4200", "")
				defer finishUnrelated()
				finish := am.beginCommandStart("alice", "4100", group)
				type lookupResult struct {
					session *SessionInfo
					managed bool
				}
				result := make(chan lookupResult, 1)
				go func() {
					s, managed := am.lockSudoSession(tc.id)
					am.mu.Unlock()
					result <- lookupResult{s, managed}
				}()

				synctest.Wait()
				published := &SessionInfo{uid: "4100", groupPath: group}
				am.mu.Lock()
				am.pidToSessionMap[42] = published
				am.mu.Unlock()
				finish()
				synctest.Wait()

				select {
				case got := <-result:
					assert.True(t, got.managed)
					if tc.wantSession {
						assert.Same(t, published, got.session)
					} else {
						assert.Nil(t, got.session)
					}
				default:
					t.Fatal("lookup waited for the unrelated command start")
				}
			})
		})
	}
}

func TestStalledCommandStartLookup(t *testing.T) {
	for _, tc := range []struct {
		name      string
		uid       string
		startUID  string
		group     string
		ancestors []int
		managed   bool
		wait      time.Duration
	}{
		{name: "verified root PID candidate", uid: "0", startUID: "0", ancestors: []int{os.Getpid()}, wait: 2 * time.Second},
		{name: "exact cgroup unmanaged UID", uid: "4300", group: "/agent/cmd", wait: 2 * time.Second},
		{name: "unrelated UID", uid: "4200"},
		{name: "unrelated UID with agent ancestor", uid: "4200", ancestors: []int{os.Getpid()}},
		{name: "pending managed UID", uid: "4100", managed: true, wait: 2 * time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				am := newTestAuthManager()
				startUID := tc.startUID
				if startUID == "" {
					startUID = "4100"
				}
				finish := am.beginCommandStart("alice", startUID, "/agent/cmd")
				defer finish()
				result := make(chan bool, 1)
				start := time.Now()
				go func() {
					session, managed := am.lockSudoSession(sudoIdentity{processUID: tc.uid, ancestors: tc.ancestors, group: tc.group})
					am.mu.Unlock()
					assert.Nil(t, session)
					result <- managed
				}()
				select {
				case managed := <-result:
					assert.Equal(t, tc.managed, managed)
					assert.Equal(t, tc.wait, time.Since(start))
				case <-time.After(3 * time.Second):
					t.Fatal("classification still waiting on stalled registration")
				}
			})
		})
	}
}

func TestStalledManagedCommandStartDeniesSudo(t *testing.T) {
	if (runtime.GOOS != "linux" && runtime.GOOS != "darwin") || os.Getuid() == 0 {
		t.Skip("requires kernel non-root UID")
	}
	synctest.Test(t, func(t *testing.T) {
		am := newTestAuthManager()
		am.UpdateBlockLocalSudo(false)
		finish := am.beginCommandStart("managed", strconv.Itoa(os.Getuid()), "")
		defer finish()
		req := SudoApprovalRequest{Type: "sudo_approval", Username: "root", PID: os.Getpid(), RequestID: strconv.Itoa(os.Getpid())}
		start := time.Now()
		client, _ := startPAMClient(t, am, req)
		select {
		case <-client.done:
		case <-time.After(3 * time.Second):
			t.Fatal("no verdict after registration timed out")
		}
		var verdict SudoApprovalResponse
		require.NoError(t, json.Unmarshal([]byte(client.output(t)), &verdict))
		assert.False(t, verdict.Approved)
		assert.Equal(t, "No Authority", verdict.Reason)
		assert.Equal(t, 2*time.Second, time.Since(start))
	})
}
