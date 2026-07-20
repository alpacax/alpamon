package runner

import (
	"encoding/json"
	"testing"
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
