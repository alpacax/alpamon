package utils

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

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
		{"unexpected value clamped", "usepam maybe\n", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, parseSSHDUsePAM(tt.out), "parseSSHDUsePAM(%q)", tt.out)
		})
	}
}
