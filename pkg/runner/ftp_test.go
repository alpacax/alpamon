//go:build !windows

// The test cases in this file encode the Unix contract for parsePath:
// hardcoded POSIX-style paths like "/tmp/file.txt" and "/home/testuser"
// are not valid wire paths on Windows (they're missing drive letters),
// so the assertions would mismatch on that platform without indicating
// a real regression. Windows coverage lives in ftp_windows_test.go.

package runner

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/alpacax/alpamon/v2/pkg/config"
	"github.com/alpacax/alpamon/v2/pkg/logger"
	"github.com/gorilla/websocket"
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

// newWiredFtpClient wires an FtpClient to a real httptest websocket peer; tests drive the pumps directly to avoid RunFtpBackground's os.Exit teardown.
func newWiredFtpClient(t *testing.T) (*FtpClient, *websocket.Conn, func()) {
	t.Helper()

	serverConnCh := make(chan *websocket.Conn, 1)
	upgrader := websocket.Upgrader{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		serverConnCh <- conn
	}))

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")
	clientConn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		srv.Close()
		t.Fatalf("failed to dial test server: %v", err)
	}

	var serverConn *websocket.Conn
	select {
	case serverConn = <-serverConnCh:
	case <-time.After(3 * time.Second):
		_ = clientConn.Close()
		srv.Close()
		t.Fatal("server did not accept the websocket upgrade")
	}

	home := t.TempDir()
	fc := &FtpClient{
		homeDirectory:    home,
		workingDirectory: home,
		log:              logger.NewFtpLogger(),
		conn:             clientConn,
		commandChan:      make(chan []byte, 1),
		responseChan:     make(chan []byte, 1),
	}
	fc.execute = fc.handleFtpCommand

	cleanup := func() {
		_ = clientConn.Close()
		_ = serverConn.Close()
		srv.Close()
	}
	return fc, serverConn, cleanup
}

// startPumps launches the read/handleCommands/write goroutines; call it after any fc.execute override so the worker can't race the assignment.
func startPumps(fc *FtpClient) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	go fc.read(ctx, cancel)
	go fc.handleCommands(ctx, cancel)
	go fc.write(ctx, cancel)
	return ctx, cancel
}

func TestFtpReadLoopStaysResponsiveDuringLongCommand(t *testing.T) {
	fc, serverConn, cleanup := newWiredFtpClient(t)
	defer cleanup()

	// execute blocks until released, pinning the worker like a long-running command.
	blocked := make(chan struct{})
	release := make(chan struct{})
	defer close(release)
	fc.execute = func(command FtpCommand, data FtpData) (CommandResult, error) {
		close(blocked)
		<-release
		return CommandResult{}, nil
	}

	ctx, cancel := startPumps(fc)
	defer cancel()

	msg, err := json.Marshal(FtpContent{Command: Pwd})
	if err != nil {
		t.Fatalf("failed to marshal command: %v", err)
	}
	if err := serverConn.WriteMessage(websocket.TextMessage, msg); err != nil {
		t.Fatalf("failed to send command: %v", err)
	}

	select {
	case <-blocked:
	case <-time.After(2 * time.Second):
		t.Fatal("worker never started executing the command")
	}

	// With the worker stuck, a responsive read loop still observes the peer's close frame and cancels.
	_ = serverConn.WriteControl(
		websocket.CloseMessage,
		websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""),
		time.Now().Add(time.Second),
	)

	select {
	case <-ctx.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("read loop did not observe close while worker was busy")
	}
}

func TestFtpWriteDeadlineCancelsOnStalledPeer(t *testing.T) {
	fc, _, cleanup := newWiredFtpClient(t)
	defer cleanup()

	// The peer (serverConn) never reads, so once the OS socket buffer fills
	// WriteMessage blocks; a short deadline must turn that into an error.
	fc.writeTimeout = 200 * time.Millisecond

	ctx, cancel := startPumps(fc)
	defer cancel()

	// Feed large payloads until the write blocks past the deadline and cancels.
	go func() {
		payload := make([]byte, 1<<20)
		for {
			select {
			case fc.responseChan <- payload:
			case <-ctx.Done():
				return
			}
		}
	}()

	select {
	case <-ctx.Done():
	case <-time.After(3 * time.Second):
		t.Fatal("stalled peer did not trigger write deadline and session teardown")
	}
}

func TestFtpCommandsAreSerializedInOrder(t *testing.T) {
	fc, serverConn, cleanup := newWiredFtpClient(t)
	defer cleanup()

	base := fc.workingDirectory
	names := []string{"dir_a", "dir_b", "dir_c", "dir_d"}

	_, cancel := startPumps(fc)
	defer cancel()

	for _, name := range names {
		msg, err := json.Marshal(FtpContent{
			Command: Mkd,
			Data:    FtpData{Path: filepath.Join(base, name)},
		})
		if err != nil {
			t.Fatalf("failed to marshal command: %v", err)
		}
		if err := serverConn.WriteMessage(websocket.TextMessage, msg); err != nil {
			t.Fatalf("failed to send command: %v", err)
		}
	}

	_ = serverConn.SetReadDeadline(time.Now().Add(3 * time.Second))
	for i := range names {
		_, raw, err := serverConn.ReadMessage()
		if err != nil {
			t.Fatalf("failed to read response %d: %v", i, err)
		}
		var result FtpResult
		if err := json.Unmarshal(raw, &result); err != nil {
			t.Fatalf("failed to unmarshal response %d: %v", i, err)
		}
		if result.Command != Mkd {
			t.Fatalf("response %d: expected command %q, got %q", i, Mkd, result.Command)
		}
		if !result.Success {
			t.Fatalf("response %d: mkd failed: %+v", i, result.Data)
		}
		// The ith response must be for the ith requested directory; identical
		// commands would let out-of-order responses slip past this loop otherwise.
		if want := filepath.Join(base, names[i]); !strings.Contains(result.Data.Message, want) {
			t.Fatalf("response %d out of order: want path %q in message, got %q", i, want, result.Data.Message)
		}
	}

	for _, name := range names {
		if _, err := os.Stat(filepath.Join(base, name)); err != nil {
			t.Fatalf("expected directory %q to exist: %v", name, err)
		}
	}
}
