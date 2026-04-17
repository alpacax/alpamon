package runner

import (
	"path/filepath"
	"runtime"
	"testing"

	"github.com/alpacax/alpamon/pkg/config"
)

func TestWirePathRoundtripUnix(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix-specific behavior")
	}

	cases := []string{"/home/foo", "/tmp/a/b", "/"}
	for _, p := range cases {
		got := toWirePath(p)
		if got != p {
			t.Errorf("toWirePath(%q) = %q, want %q (no-op on Unix)", p, got, p)
		}
		back := fromWirePath(p)
		if back != p {
			t.Errorf("fromWirePath(%q) = %q, want %q (no-op on Unix)", p, back, p)
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
		if got := toWirePath(tc.native); got != tc.wire {
			t.Errorf("toWirePath(%q) = %q, want %q", tc.native, got, tc.wire)
		}
		if got := fromWirePath(tc.wire); got != tc.native {
			t.Errorf("fromWirePath(%q) = %q, want %q", tc.wire, got, tc.native)
		}
	}

	// fromWirePath should also accept already-native input
	if got := fromWirePath(`C:\Users\foo`); got != `C:\Users\foo` {
		t.Errorf("fromWirePath(native) should pass through, got %q", got)
	}

	// Bare "/C:" (breadcrumb click on drive letter) normalizes to drive root
	if got := fromWirePath("/C:"); got != `C:\` {
		t.Errorf("fromWirePath(\"/C:\") = %q, want C:\\", got)
	}
}

func newTestFtpClient(home string) *FtpClient {
	return &FtpClient{
		homeDirectory:    home,
		workingDirectory: home,
	}
}

func TestParsePath(t *testing.T) {
	fc := newTestFtpClient("/home/testuser")

	tests := []struct {
		name    string
		path    string
		want    string
		wantErr bool
	}{
		{
			name: "absolute path",
			path: "/tmp/file.txt",
			want: "/tmp/file.txt",
		},
		{
			name: "relative path",
			path: "documents/file.txt",
			want: "/home/testuser/documents/file.txt",
		},
		{
			name: "tilde expands to working directory",
			path: "~/file.txt",
			want: "/home/testuser/file.txt",
		},
		{
			name: "dot-dot traversal is resolved",
			path: "/home/testuser/../other/file.txt",
			want: "/home/other/file.txt",
		},
		{
			name:    "null byte rejected",
			path:    "/tmp/file\x00.txt",
			wantErr: true,
		},
		{
			name:    "only null byte",
			path:    "\x00",
			wantErr: true,
		},
		{
			name: "root path",
			path: "/",
			want: "/",
		},
		{
			name: "dot resolves to working directory",
			path: ".",
			want: "/home/testuser",
		},
		{
			name: "double dot from working directory",
			path: "..",
			want: "/home",
		},
		{
			name: "path with trailing slash",
			path: "/tmp/dir/",
			want: "/tmp/dir",
		},
		{
			name: "path with double slashes",
			path: "/tmp//file.txt",
			want: "/tmp/file.txt",
		},
		{
			name: "empty path resolves to working directory",
			path: "",
			want: "/home/testuser",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := fc.parsePath(tc.path)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("parsePath(%q) expected error, got %q", tc.path, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("parsePath(%q) unexpected error: %v", tc.path, err)
			}
			if got != tc.want {
				t.Fatalf("parsePath(%q) = %q, want %q", tc.path, got, tc.want)
			}
		})
	}
}

func TestParsePath_ResultIsClean(t *testing.T) {
	fc := newTestFtpClient("/home/testuser")

	paths := []string{
		"/tmp/file.txt",
		"relative/path",
		"~/docs",
		"/a/../b/./c",
	}

	for _, p := range paths {
		got, err := fc.parsePath(p)
		if err != nil {
			t.Fatalf("parsePath(%q) unexpected error: %v", p, err)
		}
		if got != filepath.Clean(got) {
			t.Fatalf("parsePath(%q) = %q is not clean (clean = %q)", p, got, filepath.Clean(got))
		}
		if !filepath.IsAbs(got) {
			t.Fatalf("parsePath(%q) = %q is not absolute", p, got)
		}
	}
}

func TestParsePath_CwdChangesResolution(t *testing.T) {
	fc := newTestFtpClient("/home/testuser")

	// Change working directory
	fc.workingDirectory = "/var/log"

	got, err := fc.parsePath("app.log")
	if err != nil {
		t.Fatalf("parsePath unexpected error: %v", err)
	}
	if got != "/var/log/app.log" {
		t.Fatalf("parsePath(\"app.log\") with cwd=/var/log = %q, want /var/log/app.log", got)
	}

	// Tilde should expand to working directory
	got, err = fc.parsePath("~/file")
	if err != nil {
		t.Fatalf("parsePath unexpected error: %v", err)
	}
	if got != "/var/log/file" {
		t.Fatalf("parsePath(\"~/file\") with cwd=/var/log = %q, want /var/log/file", got)
	}
}

func TestValidateWebSocketURL(t *testing.T) {
	prevServerURL := config.GlobalSettings.ServerURL
	t.Cleanup(func() { config.GlobalSettings.ServerURL = prevServerURL })
	config.GlobalSettings.ServerURL = "https://console.example.com"

	tests := []struct {
		name    string
		url     string
		wantErr bool
	}{
		{
			name: "valid wss with matching host",
			url:  "wss://console.example.com/ws/channel/123",
		},
		{
			name:    "ws scheme rejected for https server",
			url:     "ws://console.example.com/ws/channel/123",
			wantErr: true,
		},
		{
			name: "case insensitive host match",
			url:  "wss://Console.Example.COM/ws/channel/123",
		},
		{
			name:    "invalid scheme http",
			url:     "http://console.example.com/ws/channel/123",
			wantErr: true,
		},
		{
			name:    "mismatched host",
			url:     "wss://evil.com/ws/channel/123",
			wantErr: true,
		},
		{
			name:    "host prefix attack",
			url:     "wss://console.example.com.evil.com/ws/channel/123",
			wantErr: true,
		},
		{
			name:    "invalid url",
			url:     "://bad",
			wantErr: true,
		},
		{
			name: "explicit default port matches implicit",
			url:  "wss://console.example.com:443/ws/channel/123",
		},
		{
			name:    "empty scheme",
			url:     "console.example.com/ws/channel/123",
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := validateWebSocketURL(tc.url)
			if tc.wantErr && err == nil {
				t.Fatalf("validateWebSocketURL(%q) expected error", tc.url)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("validateWebSocketURL(%q) unexpected error: %v", tc.url, err)
			}
		})
	}
}

func TestValidateWebSocketURL_InvalidServerURL(t *testing.T) {
	prevServerURL := config.GlobalSettings.ServerURL
	t.Cleanup(func() { config.GlobalSettings.ServerURL = prevServerURL })
	config.GlobalSettings.ServerURL = "://invalid"

	_, err := validateWebSocketURL("wss://whatever.com/ws")
	if err == nil {
		t.Fatal("expected error for invalid server URL")
	}
}

func TestValidateWebSocketURL_ServerWithExplicitPort(t *testing.T) {
	prevServerURL := config.GlobalSettings.ServerURL
	t.Cleanup(func() { config.GlobalSettings.ServerURL = prevServerURL })
	config.GlobalSettings.ServerURL = "https://console.example.com:8443"

	tests := []struct {
		name    string
		url     string
		wantErr bool
	}{
		{
			name: "same port allowed",
			url:  "wss://console.example.com:8443/ws/channel/123",
		},
		{
			name: "different port allowed",
			url:  "wss://console.example.com:9090/ws/channel/123",
		},
		{
			name: "no port allowed",
			url:  "wss://console.example.com/ws/channel/123",
		},
		{
			name:    "different host rejected",
			url:     "wss://evil.com:8443/ws/channel/123",
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := validateWebSocketURL(tc.url)
			if tc.wantErr && err == nil {
				t.Fatalf("validateWebSocketURL(%q) expected error", tc.url)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("validateWebSocketURL(%q) unexpected error: %v", tc.url, err)
			}
		})
	}
}
