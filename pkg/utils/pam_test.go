package utils

import "testing"

// TestParseSSHDUsePAM covers the sshd -T output shapes we rely on.
func TestParseSSHDUsePAM(t *testing.T) {
	tests := []struct {
		name string
		out  string
		want string
	}{
		{"enabled", "port 22\nusepam yes\npermitrootlogin no\n", "yes"},
		{"disabled", "usepam no\n", "no"},
		{"mixed case", "UsePAM Yes\n", "yes"},
		{"absent", "port 22\npermitrootlogin no\n", ""},
		{"empty", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := parseSSHDUsePAM(tt.out); got != tt.want {
				t.Errorf("parseSSHDUsePAM(%q) = %q, want %q", tt.out, got, tt.want)
			}
		})
	}
}
