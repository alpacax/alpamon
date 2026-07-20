package runner

import (
	"encoding/json"
	"net"
	"testing"
	"time"
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
