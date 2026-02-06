package runner

import "testing"

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
