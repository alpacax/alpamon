package runner

import (
	"path/filepath"
	"testing"

	"github.com/alpacax/alpamon/pkg/config"
)

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
			err := validateWebSocketURL(tc.url)
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

	err := validateWebSocketURL("wss://whatever.com/ws")
	if err == nil {
		t.Fatal("expected error for invalid server URL")
	}
}

