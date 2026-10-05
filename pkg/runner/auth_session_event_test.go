package runner

import (
	"encoding/json"
	"net"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newSessionEventPipe closes both ends on cleanup because handleSessionEvent
// leaves closing unixConn to its caller, and in these tests that is the test.
func newSessionEventPipe(t *testing.T) (server, client net.Conn) {
	t.Helper()
	server, client = net.Pipe()
	t.Cleanup(func() {
		_ = server.Close()
		_ = client.Close()
	})
	return server, client
}

// TestSessionEventRequest_ParsesWithoutOptionalFields verifies that
// rhost/tty may be absent (local console logins have no rhost).
func TestSessionEventRequest_ParsesWithoutOptionalFields(t *testing.T) {
	raw := `{"type":"session_event","username":"root","service":"login","pid":701,"ppid":700}`

	var req SessionEventRequest
	require.NoError(t, json.Unmarshal([]byte(raw), &req), "unmarshal failed")
	assert.Equal(t, "root", req.Username, "unexpected fields: %+v", req)
	assert.Equal(t, "login", req.Service, "unexpected fields: %+v", req)
	assert.Empty(t, req.RHost, "rhost/tty should default to empty")
	assert.Empty(t, req.TTY, "rhost/tty should default to empty")
}

// TestResolveSessionEvent_UnknownSessionBuildsEvent verifies that a
// session with no tracker entry produces an emittable event.
func TestResolveSessionEvent_UnknownSessionBuildsEvent(t *testing.T) {
	am := newTestAuthManager()

	req := SessionEventRequest{
		Type:     "session_event",
		Username: "alice",
		Service:  "sshd",
		RHost:    "203.0.113.5",
		TTY:      "pts/1",
		PID:      712345,
		PPID:     712340,
	}

	event, emit := am.resolveSessionEvent(req)
	require.True(t, emit, "expected emit=true for unknown session")
	assert.Equal(t, "alice", event.Username, "event fields not copied: %+v", event)
	assert.Equal(t, "sshd", event.Service, "event fields not copied: %+v", event)
	assert.Equal(t, "203.0.113.5", event.RHost, "event fields not copied: %+v", event)
	assert.Equal(t, "pts/1", event.TTY, "event fields not copied: %+v", event)
	assert.Equal(t, 712345, event.PID, "event fields not copied: %+v", event)
	assert.Equal(t, 712340, event.PPID, "event fields not copied: %+v", event)
	assert.False(t, event.Timestamp.IsZero(), "Timestamp should be set")
	_, err := uuid.Parse(event.EventID)
	assert.NoError(t, err, "EventID should be a uuid, got %q", event.EventID)
}

// TestResolveSessionEvent_EventIDIsUnique verifies each resolved session
// gets its own idempotency key, so two logins are never deduplicated into
// one server-side.
func TestResolveSessionEvent_EventIDIsUnique(t *testing.T) {
	am := newTestAuthManager()
	req := SessionEventRequest{
		Type: "session_event", Username: "alice", Service: "sshd",
		PID: 712345, PPID: 712340,
	}

	first, _ := am.resolveSessionEvent(req)
	second, _ := am.resolveSessionEvent(req)

	assert.NotEqual(t, first.EventID, second.EventID, "expected distinct EventIDs")
}

// TestResolveSessionEvent_WebshSessionSuppressed verifies that a caller
// whose ppid maps to a tracked Websh session is suppressed (e.g. su run
// inside a Websh terminal).
func TestResolveSessionEvent_WebshSessionSuppressed(t *testing.T) {
	am := newTestAuthManager()
	am.AddPIDSessionMapping(5555, &SessionInfo{
		SessionID: "sess-1",
		Requests:  make(map[string]*SudoRequest),
	})

	req := SessionEventRequest{PID: 424242, PPID: 5555, Username: "alice", Service: "su"}

	_, emit := am.resolveSessionEvent(req)
	assert.False(t, emit, "expected suppression for tracked Websh session")
}

// TestResolveSessionEvent_CommandSessionSuppressed verifies the same for
// deploy shell Command tracker entries.
func TestResolveSessionEvent_CommandSessionSuppressed(t *testing.T) {
	am := newTestAuthManager()
	am.AddPIDCommandMapping(6666, "cmd-uuid-9", "bob")

	req := SessionEventRequest{PID: 424243, PPID: 6666, Username: "bob", Service: "su"}

	_, emit := am.resolveSessionEvent(req)
	assert.False(t, emit, "expected suppression for tracked Command session")
}

// fakeParents turns a pid->ppid table into the parentOf lookup ancestorPIDs
// takes, so process topologies can be asserted without spawning processes.
func fakeParents(tree map[int]int) func(int) (int, bool) {
	return func(pid int) (int, bool) {
		ppid, ok := tree[pid]
		return ppid, ok
	}
}

// TestAncestorPIDs_WalksChain verifies the walk returns ancestors nearest
// first and stops at init.
func TestAncestorPIDs_WalksChain(t *testing.T) {
	// su(400) -> sudo monitor(300) -> sudo(200) -> websh shell(100) -> init(1)
	got := ancestorPIDs(400, fakeParents(map[int]int{400: 300, 300: 200, 200: 100, 100: 1}))

	want := []int{300, 200, 100}
	require.Equal(t, want, got, "chain")
}

// TestAncestorPIDs_StopsOnBrokenLink verifies a process reparented to init
// (setsid, nohup with a double fork, systemd-run) ends the walk instead of
// silently jumping to an unrelated tree.
func TestAncestorPIDs_StopsOnBrokenLink(t *testing.T) {
	assert.Empty(t, ancestorPIDs(400, fakeParents(map[int]int{400: 1})), "a process reparented to init has no usable ancestors")
	assert.Empty(t, ancestorPIDs(400, fakeParents(map[int]int{})), "an unreadable parent must end the walk")
}

// TestAncestorPIDs_BoundedAndLoopSafe verifies the walk cannot run away: a
// self-parenting pid terminates, and a deep chain is capped.
func TestAncestorPIDs_BoundedAndLoopSafe(t *testing.T) {
	assert.Empty(t, ancestorPIDs(400, fakeParents(map[int]int{400: 400})), "a self-parenting pid must not be walked")

	deep := make(map[int]int)
	for pid := 100; pid < 200; pid++ {
		deep[pid] = pid + 1
	}
	assert.Len(t, ancestorPIDs(100, fakeParents(deep)), maxSessionAncestorDepth, "walk depth")
}

// TestLookupSessionAncestor_SudoUsePtyTopology pins the case the direct
// (sid, ppid) pair cannot see. With sudo's use_pty on (the default on current
// Debian/Ubuntu) `sudo su -` inside Websh runs su in a session created by
// sudo's monitor, so su's sid is the monitor and su's parent is the monitor —
// neither is tracked. Only the grandparent chain still reaches the Websh PTY
// leader.
func TestLookupSessionAncestor_SudoUsePtyTopology(t *testing.T) {
	const (
		webshLeaderPID = 100
		sudoPID        = 200
		monitorPID     = 300
		suPID          = 400
	)
	am := newTestAuthManager()
	am.AddPIDSessionMapping(webshLeaderPID, &SessionInfo{
		SessionID: "sess-1",
		Requests:  make(map[string]*SudoRequest),
	})

	// su's own keys both miss: sid is the monitor's new session, ppid is the
	// monitor. This is what makes the event look non-Alpacon today.
	am.mu.RLock()
	_, direct := am.lookupSessionLocked(monitorPID, true, monitorPID)
	am.mu.RUnlock()
	require.False(t, direct, "test topology is wrong: the direct lookup must miss")

	chain := ancestorPIDs(suPID, fakeParents(map[int]int{
		suPID: monitorPID, monitorPID: sudoPID, sudoPID: webshLeaderPID, webshLeaderPID: 1,
	}))
	am.mu.RLock()
	session, found := am.lookupSessionAncestorLocked(chain)
	am.mu.RUnlock()

	require.True(t, found, "su under sudo use_pty must resolve to the Websh session via its ancestors")
	assert.Equal(t, "sess-1", session.SessionID)
}

// TestLookupSessionAncestor_UntrackedChainEmits verifies the walk does not
// over-suppress: a genuine outside login whose ancestors are all untracked
// still resolves to no session.
func TestLookupSessionAncestor_UntrackedChainEmits(t *testing.T) {
	am := newTestAuthManager()
	am.AddPIDSessionMapping(100, &SessionInfo{
		SessionID: "sess-1",
		Requests:  make(map[string]*SudoRequest),
	})

	// sshd child(900) -> sshd daemon(800) -> init.
	chain := ancestorPIDs(900, fakeParents(map[int]int{900: 800, 800: 1}))
	am.mu.RLock()
	_, found := am.lookupSessionAncestorLocked(chain)
	am.mu.RUnlock()

	assert.False(t, found, "an untracked ancestor chain must not suppress the event")
}

// TestResolveSessionEvent_TruncatesToServerLimits verifies each string is cut
// to the server's max_length. An over-length field would come back as a 400,
// which this client treats as permanent, losing the whole audit record.
func TestResolveSessionEvent_TruncatesToServerLimits(t *testing.T) {
	am := newTestAuthManager()

	event, emit := am.resolveSessionEvent(SessionEventRequest{
		Username: strings.Repeat("u", maxAccessEventUsernameLen+10),
		Service:  strings.Repeat("s", maxAccessEventServiceLen+10),
		RHost:    strings.Repeat("r", maxAccessEventRHostLen+10),
		TTY:      strings.Repeat("t", maxAccessEventTTYLen+10),
		PID:      712345,
		PPID:     712340,
	})
	require.True(t, emit, "expected emit=true for unknown session")

	for _, tc := range []struct {
		field string
		got   string
		want  int
	}{
		{"username", event.Username, maxAccessEventUsernameLen},
		{"service", event.Service, maxAccessEventServiceLen},
		{"rhost", event.RHost, maxAccessEventRHostLen},
		{"tty", event.TTY, maxAccessEventTTYLen},
	} {
		assert.Len(t, tc.got, tc.want, "%s", tc.field)
	}
}

// TestTruncateRunes_CutsOnCodepointBoundary verifies a multi-byte rune is
// never split, which would put invalid UTF-8 on the wire.
func TestTruncateRunes_CutsOnCodepointBoundary(t *testing.T) {
	got, cut := truncateRunes("héllo", 2)
	require.True(t, cut, "expected cut=true")
	assert.Equal(t, "hé", got)
	assert.True(t, utf8.ValidString(got), "truncation produced invalid UTF-8: %q", got)

	got, cut = truncateRunes("héllo", 5)
	assert.False(t, cut, "a string within the limit must pass through unchanged")
	assert.Equal(t, "héllo", got, "a string within the limit must pass through unchanged")
}

// TestResolveSessionEvent_ClampsNegativePPID verifies a malformed frame cannot
// produce a payload the server's PositiveIntegerField would reject outright.
func TestResolveSessionEvent_ClampsNegativePPID(t *testing.T) {
	am := newTestAuthManager()

	event, emit := am.resolveSessionEvent(SessionEventRequest{
		Username: "alice", Service: "sshd", PID: 712345, PPID: -1,
	})
	require.True(t, emit, "expected emit=true for unknown session")
	assert.Equal(t, 0, event.PPID)
}

// readSessionEventAck reads and decodes the ack written to the client
// end of a net.Pipe by handleSessionEvent.
func readSessionEventAck(t *testing.T, client net.Conn) SessionEventResponse {
	t.Helper()
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1024)
	n, err := client.Read(buf)
	require.NoError(t, err, "failed to read ack")
	var resp SessionEventResponse
	require.NoErrorf(t, json.Unmarshal(buf[:n], &resp), "invalid ack JSON %q", buf[:n])
	return resp
}

// handleSessionEventSync runs handleSessionEvent to completion and returns
// the ack PAM would have read.
func handleSessionEventSync(t *testing.T, am *AuthManager, raw []byte) SessionEventResponse {
	t.Helper()
	server, client := newSessionEventPipe(t)
	done := make(chan struct{})
	go func() {
		am.handleSessionEvent(raw, server)
		close(done)
	}()
	resp := readSessionEventAck(t, client)
	<-done
	return resp
}

func newSessionEventTestAuthManager(t *testing.T) (*AuthManager, *accessEventOutbox) {
	t.Helper()
	o := newTestOutbox(t, newFakeOutboxClock(), &fakeAccessEventSender{})
	am := newTestAuthManager()
	am.outbox = o
	return am, o
}

// TestHandleSessionEvent_AcksAndStores verifies the happy path: a valid
// non-Alpacon session_event is acked and the event lands in the outbox.
func TestHandleSessionEvent_AcksAndStores(t *testing.T) {
	am, o := newSessionEventTestAuthManager(t)
	am.detectLocalAccess = true

	raw := []byte(`{"type":"session_event","username":"alice","service":"sshd","rhost":"203.0.113.5","tty":"pts/1","pid":712345,"ppid":712340}`)
	resp := handleSessionEventSync(t, am, raw)
	assert.Equal(t, "session_event_response", resp.Type, "unexpected ack: %+v", resp)
	assert.True(t, resp.Received, "unexpected ack: %+v", resp)

	rows := outboxRows(t, o)
	require.Len(t, rows, 1, "the event must be stored")
	var ev NonAlpaconAccessEvent
	require.NoError(t, json.Unmarshal(rows[0].Payload, &ev))
	assert.Equal(t, rows[0].ID, ev.EventID, "the row is keyed by the event id")
	assert.Equal(t, "alice", ev.Username, "unexpected event: %+v", ev)
	assert.Equal(t, "sshd", ev.Service, "unexpected event: %+v", ev)
	assert.True(t, ev.Timestamp.Equal(rows[0].CreatedAt), "the row keeps the host-recorded time")
}

// TestHandleSessionEvent_MalformedJSONAcksFalse verifies fail-open
// behavior on garbage input: PAM still gets an answer, nothing is stored.
func TestHandleSessionEvent_MalformedJSONAcksFalse(t *testing.T) {
	am, o := newSessionEventTestAuthManager(t)
	am.detectLocalAccess = true

	resp := handleSessionEventSync(t, am, []byte(`{not-json`))
	assert.False(t, resp.Received, "expected received=false for malformed input, got %+v", resp)
	assert.Empty(t, outboxRows(t, o), "must not store malformed input")
}

// TestHandleSessionEvent_SuppressedStillAcks verifies Alpacon-originated
// sessions are acked but not stored.
func TestHandleSessionEvent_SuppressedStillAcks(t *testing.T) {
	am, o := newSessionEventTestAuthManager(t)
	am.detectLocalAccess = true
	am.AddPIDSessionMapping(5555, &SessionInfo{
		SessionID: "sess-1",
		Requests:  make(map[string]*SudoRequest),
	})

	raw := []byte(`{"type":"session_event","username":"alice","service":"su","pid":424242,"ppid":5555}`)
	resp := handleSessionEventSync(t, am, raw)
	assert.Truef(t, resp.Received, "suppressed events must still ack true, got %+v", resp)
	assert.Empty(t, outboxRows(t, o), "must not store a tracked Alpacon session")
}

// TestHandleSessionEvent_FlagOffDoesNotStore verifies the policy gate:
// detection default-off means ack-only behavior.
func TestHandleSessionEvent_FlagOffDoesNotStore(t *testing.T) {
	am, o := newSessionEventTestAuthManager(t)

	raw := []byte(`{"type":"session_event","username":"alice","service":"sshd","pid":712345,"ppid":712340}`)
	resp := handleSessionEventSync(t, am, raw)
	assert.Truef(t, resp.Received, "flag-off events must still ack true, got %+v", resp)
	assert.Empty(t, outboxRows(t, o), "must not store while detect_local_access is off")
}

// TestHandleSessionEvent_WithoutStoreStillAcks covers an AuthManager that was
// never given a database: the ack still goes out and nothing panics.
func TestHandleSessionEvent_WithoutStoreStillAcks(t *testing.T) {
	am := newTestAuthManager()
	am.detectLocalAccess = true

	raw := []byte(`{"type":"session_event","username":"alice","service":"sshd","pid":712345,"ppid":712340}`)
	assert.True(t, handleSessionEventSync(t, am, raw).Received)
}

// TestUpdateDetectLocalAccess verifies the policy flag setter mirrors
// UpdateBlockLocalSudo semantics.
func TestUpdateDetectLocalAccess(t *testing.T) {
	am := newTestAuthManager()

	require.False(t, am.detectLocalAccess, "detect_local_access must default to false")
	am.UpdateDetectLocalAccess(true)
	assert.True(t, am.detectLocalAccess, "expected detect_local_access=true after update")
	am.UpdateDetectLocalAccess(false)
	assert.False(t, am.detectLocalAccess, "expected detect_local_access=false after update")
}

// TestAccessPolicy_ParsesDetectLocalAccess verifies the sync payload
// field mapping.
func TestAccessPolicy_ParsesDetectLocalAccess(t *testing.T) {
	raw := `{"block_local_sudo":false,"detect_local_access":true}`

	var policy AccessPolicy
	require.NoError(t, json.Unmarshal([]byte(raw), &policy), "unmarshal failed")
	assert.True(t, policy.DetectLocalAccess, "expected DetectLocalAccess=true")
	assert.False(t, policy.BlockLocalSudo, "expected BlockLocalSudo=false")
}
