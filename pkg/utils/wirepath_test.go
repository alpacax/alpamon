package utils

import (
	"runtime"
	"testing"
)

func TestWirePathRoundtripUnix(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix-specific behavior")
	}

	cases := []string{"/home/foo", "/tmp/a/b", "/"}
	for _, p := range cases {
		if got := ToWirePath(p); got != p {
			t.Errorf("ToWirePath(%q) = %q, want %q (no-op on Unix)", p, got, p)
		}
		if got := FromWirePath(p); got != p {
			t.Errorf("FromWirePath(%q) = %q, want %q (no-op on Unix)", p, got, p)
		}
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
		if got := ToWirePath(tc.native); got != tc.wire {
			t.Errorf("ToWirePath(%q) = %q, want %q", tc.native, got, tc.wire)
		}
		if got := FromWirePath(tc.wire); got != tc.native {
			t.Errorf("FromWirePath(%q) = %q, want %q", tc.wire, got, tc.native)
		}
	}

	// FromWirePath should also accept already-native input
	if got := FromWirePath(`C:\Users\foo`); got != `C:\Users\foo` {
		t.Errorf("FromWirePath(native) should pass through, got %q", got)
	}

	// Bare "/C:" (breadcrumb click on drive letter) normalizes to drive root
	if got := FromWirePath("/C:"); got != `C:\` {
		t.Errorf("FromWirePath(\"/C:\") = %q, want C:\\", got)
	}
}
