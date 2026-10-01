package utils

import (
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestWirePathRoundtripUnix(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix-specific behavior")
	}

	cases := []string{"/home/foo", "/tmp/a/b", "/"}
	for _, p := range cases {
		assert.Equal(t, p, ToWirePath(p), "ToWirePath(%q) (no-op on Unix)", p)
		assert.Equal(t, p, FromWirePath(p), "FromWirePath(%q) (no-op on Unix)", p)
	}
}

func TestWirePathRoundtripWindows(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows-specific behavior")
	}

	cases := []struct {
		native string
		wire   string
	}{
		{`C:\Users\Administrator`, "/C:/Users/Administrator"},
		{`c:\foo\bar`, "/c:/foo/bar"},
		{`C:\`, "/C:/"},
	}
	for _, tc := range cases {
		assert.Equal(t, tc.wire, ToWirePath(tc.native), "ToWirePath(%q)", tc.native)
		assert.Equal(t, tc.native, FromWirePath(tc.wire), "FromWirePath(%q)", tc.wire)
	}

	// FromWirePath should also accept already-native input
	assert.Equal(t, `C:\Users\foo`, FromWirePath(`C:\Users\foo`), "FromWirePath(native) should pass through")

	// Bare "/C:" (breadcrumb click on drive letter) normalizes to drive root
	assert.Equal(t, `C:\`, FromWirePath("/C:"), "FromWirePath(\"/C:\")")
}
