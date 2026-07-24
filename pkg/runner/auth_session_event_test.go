package runner

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alpacax/alpamon/v2/pkg/scheduler"
	"github.com/google/uuid"
)

// TestSessionEventRequest_ParsesWithoutOptionalFields verifies that
// rhost/tty may be absent (local console logins have no rhost).
func TestSessionEventRequest_ParsesWithoutOptionalFields(t *testing.T) {
	raw := `{"type":"session_event","username":"root","service":"login","pid":701,"ppid":700}`

	var req SessionEventRequest
	if err := json.Unmarshal([]byte(raw), &req); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if req.Username != "root" || req.Service != "login" {
		t.Errorf("unexpected fields: %+v", req)
	}
	if req.RHost != "" || req.TTY != "" {
		t.Errorf("rhost/tty should default to empty, got %q %q", req.RHost, req.TTY)
	}
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
	if !emit {
		t.Fatal("expected emit=true for unknown session")
	}
	if event.Username != "alice" || event.Service != "sshd" ||
		event.RHost != "203.0.113.5" || event.TTY != "pts/1" ||
		event.PID != 712345 || event.PPID != 712340 {
		t.Errorf("event fields not copied: %+v", event)
	}
	if event.Timestamp.IsZero() {
		t.Error("Timestamp should be set")
	}
	if _, err := uuid.Parse(event.EventID); err != nil {
		t.Errorf("EventID should be a uuid, got %q: %v", event.EventID, err)
	}
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

	if first.EventID == second.EventID {
		t.Errorf("expected distinct EventIDs, got %q twice", first.EventID)
	}
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
	if emit {
		t.Error("expected suppression for tracked Websh session")
	}
}

// TestResolveSessionEvent_CommandSessionSuppressed verifies the same for
// deploy shell Command tracker entries.
func TestResolveSessionEvent_CommandSessionSuppressed(t *testing.T) {
	am := newTestAuthManager()
	am.AddPIDCommandMapping(6666, "cmd-uuid-9", "bob")

	req := SessionEventRequest{PID: 424243, PPID: 6666, Username: "bob", Service: "su"}

	_, emit := am.resolveSessionEvent(req)
	if emit {
		t.Error("expected suppression for tracked Command session")
	}
}

// readSessionEventAck reads and decodes the ack written to the client
// end of a net.Pipe by handleSessionEvent.
func readSessionEventAck(t *testing.T, client net.Conn) SessionEventResponse {
	t.Helper()
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1024)
	n, err := client.Read(buf)
	if err != nil {
		t.Fatalf("failed to read ack: %v", err)
	}
	var resp SessionEventResponse
	if err := json.Unmarshal(buf[:n], &resp); err != nil {
		t.Fatalf("invalid ack JSON %q: %v", buf[:n], err)
	}
	return resp
}

// TestHandleSessionEvent_AcksAndEmits verifies the happy path: a valid
// non-Alpacon session_event is acked and the event reaches the emitter.
func TestHandleSessionEvent_AcksAndEmits(t *testing.T) {
	am := newTestAuthManager()
	am.detectLocalAccess = true
	emitted := make(chan NonAlpaconAccessEvent, 1)
	am.emitAccessEventFn = func(ev NonAlpaconAccessEvent) { emitted <- ev }

	server, client := net.Pipe()
	raw := []byte(`{"type":"session_event","username":"alice","service":"sshd","rhost":"203.0.113.5","tty":"pts/1","pid":712345,"ppid":712340}`)
	go am.handleSessionEvent(raw, server)

	resp := readSessionEventAck(t, client)
	if resp.Type != "session_event_response" || !resp.Received {
		t.Errorf("unexpected ack: %+v", resp)
	}

	select {
	case ev := <-emitted:
		if ev.Username != "alice" || ev.Service != "sshd" {
			t.Errorf("unexpected event: %+v", ev)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("event was not emitted")
	}
}

// TestHandleSessionEvent_MalformedJSONAcksFalse verifies fail-open
// behavior on garbage input: PAM still gets an answer, nothing emits.
func TestHandleSessionEvent_MalformedJSONAcksFalse(t *testing.T) {
	am := newTestAuthManager()
	am.detectLocalAccess = true
	am.emitAccessEventFn = func(ev NonAlpaconAccessEvent) {
		t.Error("must not emit on malformed input")
	}

	server, client := net.Pipe()
	go am.handleSessionEvent([]byte(`{not-json`), server)

	resp := readSessionEventAck(t, client)
	if resp.Received {
		t.Errorf("expected received=false for malformed input, got %+v", resp)
	}
}

// TestHandleSessionEvent_SuppressedStillAcks verifies Alpacon-originated
// sessions are acked but not emitted.
func TestHandleSessionEvent_SuppressedStillAcks(t *testing.T) {
	am := newTestAuthManager()
	am.detectLocalAccess = true
	am.AddPIDSessionMapping(5555, &SessionInfo{
		SessionID: "sess-1",
		Requests:  make(map[string]*SudoRequest),
	})
	am.emitAccessEventFn = func(ev NonAlpaconAccessEvent) {
		t.Error("must not emit for tracked Alpacon session")
	}

	server, client := net.Pipe()
	raw := []byte(`{"type":"session_event","username":"alice","service":"su","pid":424242,"ppid":5555}`)
	go am.handleSessionEvent(raw, server)

	resp := readSessionEventAck(t, client)
	if !resp.Received {
		t.Errorf("suppressed events must still ack true, got %+v", resp)
	}
	time.Sleep(100 * time.Millisecond) // give a wrong emit a chance to fire
}

// TestHandleSessionEvent_DropsWhenEmitConcurrencyExhausted verifies the
// non-blocking bound: when every emit slot is occupied, a further
// session_event is still acked but its emission is dropped instead of
// spawning an unbounded goroutine.
func TestHandleSessionEvent_DropsWhenEmitConcurrencyExhausted(t *testing.T) {
	am := newTestAuthManager()
	am.detectLocalAccess = true
	am.emitSem = make(chan struct{}, 1) // force a single emit slot

	entered := make(chan struct{}, 2)
	release := make(chan struct{})
	am.emitAccessEventFn = func(ev NonAlpaconAccessEvent) {
		entered <- struct{}{}
		<-release // hold the slot until the test releases it
	}
	defer close(release)

	raw := []byte(`{"type":"session_event","username":"alice","service":"sshd","pid":712345,"ppid":712340}`)

	// First event acquires the only slot and blocks inside emitFn.
	server1, client1 := net.Pipe()
	go am.handleSessionEvent(raw, server1)
	if resp := readSessionEventAck(t, client1); !resp.Received {
		t.Fatalf("first event must ack true, got %+v", resp)
	}
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("first emit never started")
	}

	// Second event finds the slot full: it must still ack but not emit.
	server2, client2 := net.Pipe()
	go am.handleSessionEvent(raw, server2)
	if resp := readSessionEventAck(t, client2); !resp.Received {
		t.Fatalf("dropped event must still ack true, got %+v", resp)
	}
	select {
	case <-entered:
		t.Error("second event exceeded the concurrency limit and must be dropped")
	case <-time.After(100 * time.Millisecond):
	}
}

// TestHandleSessionEvent_FlagOffDoesNotEmit verifies the policy gate:
// detection default-off means ack-only behavior.
func TestHandleSessionEvent_FlagOffDoesNotEmit(t *testing.T) {
	am := newTestAuthManager()
	am.emitAccessEventFn = func(ev NonAlpaconAccessEvent) {
		t.Error("must not emit while detect_local_access is off")
	}

	server, client := net.Pipe()
	raw := []byte(`{"type":"session_event","username":"alice","service":"sshd","pid":712345,"ppid":712340}`)
	go am.handleSessionEvent(raw, server)

	resp := readSessionEventAck(t, client)
	if !resp.Received {
		t.Errorf("flag-off events must still ack true, got %+v", resp)
	}
	time.Sleep(100 * time.Millisecond)
}

// newEmitTestAuthManager wires an AuthManager whose session points at the
// given test server URL, so emitAccessEvent's real HTTP/retry path can be
// exercised directly instead of through the emitAccessEventFn stub.
func newEmitTestAuthManager(baseURL string) *AuthManager {
	am := newTestAuthManager()
	am.ctx = context.Background()
	am.session = &scheduler.Session{BaseURL: baseURL, Client: http.DefaultClient}
	return am
}

// TestEmitAccessEvent_DropsOn404 verifies the Phase-2-not-deployed case posts
// once and gives up quietly (no retry).
func TestEmitAccessEvent_DropsOn404(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	newEmitTestAuthManager(srv.URL).emitAccessEvent(NonAlpaconAccessEvent{Username: "a", Service: "sshd", PID: 1})

	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Errorf("404 must not be retried; got %d calls", got)
	}
}

// TestEmitAccessEvent_DropsOnRejection verifies a non-429 4xx is permanent:
// posted once, then dropped.
func TestEmitAccessEvent_DropsOnRejection(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	newEmitTestAuthManager(srv.URL).emitAccessEvent(NonAlpaconAccessEvent{Username: "a", Service: "sshd", PID: 1})

	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Errorf("a 4xx rejection must not be retried; got %d calls", got)
	}
}

// TestEmitAccessEvent_RetriesOn429 verifies 429 is transient: the event is
// retried (not dropped) and succeeds once the server stops throttling.
func TestEmitAccessEvent_RetriesOn429(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if atomic.AddInt32(&calls, 1) == 1 {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()

	newEmitTestAuthManager(srv.URL).emitAccessEvent(NonAlpaconAccessEvent{Username: "a", Service: "sshd", PID: 1})

	if got := atomic.LoadInt32(&calls); got != 2 {
		t.Errorf("429 must be retried then succeed; got %d calls", got)
	}
}

// TestUpdateDetectLocalAccess verifies the policy flag setter mirrors
// UpdateBlockLocalSudo semantics.
func TestUpdateDetectLocalAccess(t *testing.T) {
	am := newTestAuthManager()

	if am.detectLocalAccess {
		t.Fatal("detect_local_access must default to false")
	}
	am.UpdateDetectLocalAccess(true)
	if !am.detectLocalAccess {
		t.Error("expected detect_local_access=true after update")
	}
	am.UpdateDetectLocalAccess(false)
	if am.detectLocalAccess {
		t.Error("expected detect_local_access=false after update")
	}
}

// TestAccessPolicy_ParsesDetectLocalAccess verifies the sync payload
// field mapping.
func TestAccessPolicy_ParsesDetectLocalAccess(t *testing.T) {
	raw := `{"block_local_sudo":false,"detect_local_access":true}`

	var policy AccessPolicy
	if err := json.Unmarshal([]byte(raw), &policy); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if !policy.DetectLocalAccess {
		t.Error("expected DetectLocalAccess=true")
	}
	if policy.BlockLocalSudo {
		t.Error("expected BlockLocalSudo=false")
	}
}
