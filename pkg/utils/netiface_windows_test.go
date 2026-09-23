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
		{"loopback", "Loopback Pseudo-Interface 1", true},
		{"isatap", "isatap.localdomain", true},
		{"teredo", "Teredo Tunneling Pseudo-Interface", true},
		{"6to4", "6to4 Adapter", true},
		{"ethernet", "Ethernet", false},
		{"wireless", "Wi-Fi", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.virtual, hasVirtualIfacePrefix(tt.iface),
				"hasVirtualIfacePrefix(%q)", tt.iface)
		})
	}
}
