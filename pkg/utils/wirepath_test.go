package utils

import (
	"os"
	"path/filepath"
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
			{"prefix substring does not pass", `C:\Users\alice`, `C:\Users\alicex\a.txt`, true},
			{"empty home rejects", ``, `C:\anything`, true},
		}
	} else {
		cases = []row{
			{"exact home", "/home/alice", "/home/alice", false},
			{"child file", "/home/alice", "/home/alice/docs/a.txt", false},
			{"parent dir escape", "/home/alice", "/home", true},
			{"system file escape", "/home/alice", "/etc/passwd", true},
			{"sibling user escape", "/home/alice", "/home/bob/a.txt", true},
			{"prefix substring does not pass", "/home/alice", "/home/alicex/a.txt", true},
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

func TestResolveSymlinksBestEffort(t *testing.T) {
	if runtime.GOOS == "windows" {
		// Creating symlinks on Windows requires either Admin or
		// Developer Mode. Skip on Windows; the unit is exercised via
		// the Unix test below which covers the code paths.
		t.Skip("Windows symlink creation requires elevated permissions")
	}

	tmp, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("resolve tmp: %v", err)
	}
	realDir := filepath.Join(tmp, "real")
	if err := os.Mkdir(realDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	realFile := filepath.Join(realDir, "a.txt")
	if err := os.WriteFile(realFile, []byte("hi"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	linkDir := filepath.Join(tmp, "link")
	if err := os.Symlink(realDir, linkDir); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	t.Run("existing file through symlink", func(t *testing.T) {
		got, err := ResolveSymlinksBestEffort(filepath.Join(linkDir, "a.txt"))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != realFile {
			t.Errorf("got %q, want %q", got, realFile)
		}
	})

	t.Run("nonexistent leaf under symlinked parent", func(t *testing.T) {
		// Path doesn't exist yet, but the parent symlink should still resolve.
		got, err := ResolveSymlinksBestEffort(filepath.Join(linkDir, "newfile.txt"))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		want := filepath.Join(realDir, "newfile.txt")
		if got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})

	t.Run("empty path rejected", func(t *testing.T) {
		if _, err := ResolveSymlinksBestEffort(""); err == nil {
			t.Error("expected error for empty path")
		}
	})
}

func TestResolveAndEnsureUnderHome_SymlinkEscape(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows symlink creation requires elevated permissions")
	}

	tmp, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("resolve tmp: %v", err)
	}
	home := filepath.Join(tmp, "home")
	if err := os.Mkdir(home, 0o755); err != nil {
		t.Fatalf("mkdir home: %v", err)
	}
	outside := filepath.Join(tmp, "outside")
	if err := os.Mkdir(outside, 0o755); err != nil {
		t.Fatalf("mkdir outside: %v", err)
	}
	secret := filepath.Join(outside, "secret.txt")
	if err := os.WriteFile(secret, []byte("x"), 0o600); err != nil {
		t.Fatalf("write secret: %v", err)
	}

	// User plants a symlink inside home pointing at outside.
	evil := filepath.Join(home, "evil")
	if err := os.Symlink(outside, evil); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	// Lexical containment would accept /home/evil/secret.txt, but the
	// resolver must reject it because it actually lives outside home.
	via := filepath.Join(evil, "secret.txt")
	if _, err := ResolveAndEnsureUnderHome(home, via); err == nil {
		t.Fatal("expected containment error for symlink escape, got nil")
	}
}
