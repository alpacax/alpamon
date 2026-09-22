package utils

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPlatformVirtualIfacePrefixes(t *testing.T) {
	tests := []struct {
		name    string
		iface   string
		virtual bool
	}{
		{"utun", "utun0", true},
		{"utun with a higher index", "utun3", true},
		{"awdl", "awdl0", true},
		{"llw", "llw0", true},
		{"bridge", "bridge0", true},
		{"anpi", "anpi0", true},
		{"ap", "ap1", true},
		{"ethernet", "en0", false},
		{"wireless", "en1", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.virtual, hasVirtualIfacePrefix(tt.iface),
				"hasVirtualIfacePrefix(%q)", tt.iface)
		})
	}
}
