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

func TestEnsureUnderHome(t *testing.T) {
	type row struct {
		name    string
		home    string
		target  string
		wantErr bool
	}

	var cases []row
	if runtime.GOOS == "windows" {
		cases = []row{
			{"exact home", `C:\Users\alice`, `C:\Users\alice`, false},
			{"child file", `C:\Users\alice`, `C:\Users\alice\docs\a.txt`, false},
			{"parent dir escape", `C:\Users\alice`, `C:\Users`, true},
			{"system file escape", `C:\Users\alice`, `C:\Windows\System32\config\SAM`, true},
			{"different volume", `C:\Users\alice`, `D:\foo`, true},
			{"case-insensitive child", `C:\Users\Alice`, `c:\users\alice\docs\a.txt`, false},
			{"sibling user escape", `C:\Users\alice`, `C:\Users\bob\a.txt`, true},
			{"empty home rejects", ``, `C:\anything`, true},
		}
	} else {
		cases = []row{
			{"exact home", "/home/alice", "/home/alice", false},
			{"child file", "/home/alice", "/home/alice/docs/a.txt", false},
			{"parent dir escape", "/home/alice", "/home", true},
			{"system file escape", "/home/alice", "/etc/passwd", true},
			{"sibling user escape", "/home/alice", "/home/bob/a.txt", true},
			{"empty home rejects", "", "/anything", true},
		}
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := EnsureUnderHome(tc.home, tc.target)
			if tc.wantErr && err == nil {
				t.Errorf("EnsureUnderHome(%q, %q) expected error", tc.home, tc.target)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("EnsureUnderHome(%q, %q) unexpected error: %v", tc.home, tc.target, err)
			}
		})
	}
}
