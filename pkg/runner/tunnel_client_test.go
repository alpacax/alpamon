package runner

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestIsValidSessionID(t *testing.T) {
	tests := []struct {
		name      string
		sessionID string
		want      bool
	}{
		{name: "valid alphanumeric", sessionID: "session123", want: true},
		{name: "valid underscore", sessionID: "session_123", want: true},
		{name: "valid hyphen", sessionID: "session-123", want: true},
		{name: "invalid empty", sessionID: "", want: false},
		{name: "invalid slash", sessionID: "session/123", want: false},
		{name: "invalid backslash", sessionID: `session\123`, want: false},
		{name: "invalid traversal", sessionID: "../session", want: false},
		{name: "invalid dot sequence", sessionID: "a..b", want: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := IsValidSessionID(tc.sessionID)
			if got != tc.want {
				t.Fatalf("IsValidSessionID(%q) = %v, want %v", tc.sessionID, got, tc.want)
			}
		})
	}
}

func TestGetHTTPStatusForHealth(t *testing.T) {
	tests := []struct {
		name   string
		status string
		want   int
	}{
		{name: "ready", status: "ready", want: 200},
		{name: "installing", status: "installing", want: 503},
		{name: "starting", status: "starting", want: 503},
		{name: "error maps to internal server error", status: "error", want: 500},
		{name: "unknown status maps to internal server error", status: "something-else", want: 500},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := getHTTPStatusForHealth(tc.status)
			if got != tc.want {
				t.Fatalf("getHTTPStatusForHealth(%q) = %d, want %d", tc.status, got, tc.want)
			}
		})
	}
}

func TestBuildHealthResponseBody(t *testing.T) {
	t.Run("status only omits empty error", func(t *testing.T) {
		body := buildHealthResponseBody("ready", "")

		var decoded map[string]interface{}
		if err := json.Unmarshal([]byte(body), &decoded); err != nil {
			t.Fatalf("buildHealthResponseBody returned invalid JSON: %v", err)
		}
		if decoded["status"] != "ready" {
			t.Fatalf("status = %v, want ready", decoded["status"])
		}
		if _, exists := decoded["error"]; exists {
			t.Fatalf("error field should be omitted when empty, got: %v", decoded["error"])
		}
	})

	t.Run("includes error field when provided", func(t *testing.T) {
		body := buildHealthResponseBody("error", "startup failed")

		var decoded map[string]interface{}
		if err := json.Unmarshal([]byte(body), &decoded); err != nil {
			t.Fatalf("buildHealthResponseBody returned invalid JSON: %v", err)
		}
		if decoded["status"] != "error" {
			t.Fatalf("status = %v, want error", decoded["status"])
		}
		if decoded["error"] != "startup failed" {
			t.Fatalf("error = %v, want startup failed", decoded["error"])
		}
	})
}

func TestResolveTargetPort(t *testing.T) {
	tc := &TunnelClient{}
	tc.targetPort.Store(3000)

	tests := []struct {
		name       string
		remotePort string
		wantPort   int
		wantErr    bool
	}{
		{name: "empty uses default target port", remotePort: "", wantPort: 3000, wantErr: false},
		{name: "valid custom port", remotePort: "8080", wantPort: 8080, wantErr: false},
		{name: "zero port rejected", remotePort: "0", wantPort: 0, wantErr: true},
		{name: "out of range port rejected", remotePort: "65536", wantPort: 0, wantErr: true},
		{name: "non numeric rejected", remotePort: "abc", wantPort: 0, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotPort, err := tc.resolveTargetPort(tt.remotePort)
			if (err != nil) != tt.wantErr {
				t.Fatalf("resolveTargetPort(%q) error = %v, wantErr %v", tt.remotePort, err, tt.wantErr)
			}
			if gotPort != tt.wantPort {
				t.Fatalf("resolveTargetPort(%q) = %d, want %d", tt.remotePort, gotPort, tt.wantPort)
			}
		})
	}
}

func TestStartTunnelDaemonInvalidSessionID(t *testing.T) {
	tests := []struct {
		name      string
		sessionID string
	}{
		{name: "traversal pattern", sessionID: "../bad"},
		{name: "path separator", sessionID: "bad/session"},
		{name: "backslash separator", sessionID: `bad\session`},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			client := &TunnelClient{sessionID: tc.sessionID}

			err := client.startTunnelDaemon()
			if err == nil {
				t.Fatalf("startTunnelDaemon(%q) expected error, got nil", tc.sessionID)
			}
			if !strings.Contains(err.Error(), "invalid session ID") {
				t.Fatalf("startTunnelDaemon(%q) error = %v, want contains %q", tc.sessionID, err, "invalid session ID")
			}
			if client.daemonCmd != nil {
				t.Fatalf("daemonCmd should remain nil for invalid session ID")
			}
			if client.daemonSocket != "" {
				t.Fatalf("daemonSocket should remain empty for invalid session ID, got %q", client.daemonSocket)
			}
		})
	}
}

func TestCloseAllActiveTunnels(t *testing.T) {
	t.Run("closes all tunnels and clears map", func(t *testing.T) {
		activeTunnelsMu.Lock()
		activeTunnels = make(map[string]*TunnelClient)
		activeTunnelsMu.Unlock()

		ctx1, cancel1 := context.WithCancel(context.Background())
		tc1 := &TunnelClient{sessionID: "s1", ctx: ctx1, cancel: cancel1}
		ctx2, cancel2 := context.WithCancel(context.Background())
		tc2 := &TunnelClient{sessionID: "s2", ctx: ctx2, cancel: cancel2}

		RegisterTunnel("s1", tc1)
		RegisterTunnel("s2", tc2)

		CloseAllActiveTunnels()

		activeTunnelsMu.RLock()
		remaining := len(activeTunnels)
		activeTunnelsMu.RUnlock()

		if remaining != 0 {
			t.Fatalf("expected 0 active tunnels after CloseAll, got %d", remaining)
		}
		if ctx1.Err() == nil {
			t.Fatalf("expected tc1 context to be cancelled")
		}
		if ctx2.Err() == nil {
			t.Fatalf("expected tc2 context to be cancelled")
		}
	})

	t.Run("safe on empty map", func(t *testing.T) {
		activeTunnelsMu.Lock()
		activeTunnels = make(map[string]*TunnelClient)
		activeTunnelsMu.Unlock()

		CloseAllActiveTunnels() // should not panic
	})

	t.Run("double close is safe", func(t *testing.T) {
		activeTunnelsMu.Lock()
		activeTunnels = make(map[string]*TunnelClient)
		activeTunnelsMu.Unlock()

		ctx, cancel := context.WithCancel(context.Background())
		tc := &TunnelClient{sessionID: "s3", ctx: ctx, cancel: cancel}
		RegisterTunnel("s3", tc)

		CloseAllActiveTunnels()
		tc.Close() // second close should not panic (sync.Once)
	})
}
