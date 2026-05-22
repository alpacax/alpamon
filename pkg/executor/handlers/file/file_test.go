package file

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/alpacax/alpamon/pkg/executor/handlers/common"
	"github.com/alpacax/alpamon/pkg/utils"
)

func TestFileHandler_Validate(t *testing.T) {
	handler := NewFileHandler(common.NewMockCommandExecutor(t), nil)

	tests := []struct {
		name    string
		cmd     string
		args    *common.CommandArgs
		wantErr bool
	}{
		{
			name: "upload valid",
			cmd:  "upload",
			args: &common.CommandArgs{
				Username: "testuser",
				Paths:    []string{"/tmp/file.txt"},
			},
			wantErr: false,
		},
		{
			name: "upload missing username",
			cmd:  "upload",
			args: &common.CommandArgs{
				Paths: []string{"/tmp/file.txt"},
			},
			wantErr: true,
		},
		{
			name: "upload missing paths",
			cmd:  "upload",
			args: &common.CommandArgs{
				Username: "testuser",
			},
			wantErr: true,
		},
		{
			name: "download valid with content",
			cmd:  "download",
			args: &common.CommandArgs{
				Username: "testuser",
				Path:     "/tmp/file.txt",
				Content:  "test",
			},
			wantErr: false,
		},
		{
			name: "download valid with files",
			cmd:  "download",
			args: &common.CommandArgs{
				Username: "testuser",
				Files: []common.File{
					{
						Path:    "/tmp/file.txt",
						Content: "test",
					},
				},
			},
			wantErr: false,
		},
		{
			name: "download missing username",
			cmd:  "download",
			args: &common.CommandArgs{
				Path:    "/tmp/file.txt",
				Content: "test",
			},
			wantErr: true,
		},
		{
			name: "download missing content and files",
			cmd:  "download",
			args: &common.CommandArgs{
				Username: "testuser",
			},
			wantErr: true,
		},
		{
			name:    "unknown command",
			cmd:     "unknown",
			args:    &common.CommandArgs{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := handler.Validate(tt.cmd, tt.args)
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestFileHandler_Execute_UnknownCommand(t *testing.T) {
	handler := NewFileHandler(common.NewMockCommandExecutor(t), nil)
	ctx := context.Background()

	exitCode, _, err := handler.Execute(ctx, "unknown", &common.CommandArgs{})

	if err == nil {
		t.Error("Execute() expected error for unknown command")
	}
	if exitCode != 1 {
		t.Errorf("Execute() exitCode = %v, want 1", exitCode)
	}
}

func TestFileHandler_Execute_UploadNoPaths(t *testing.T) {
	handler := NewFileHandler(common.NewMockCommandExecutor(t), nil)
	ctx := context.Background()

	args := &common.CommandArgs{
		Username:  "testuser",
		Groupname: "testgroup",
		Paths:     []string{},
	}

	exitCode, output, err := handler.Execute(ctx, "upload", args)

	if err != nil {
		t.Errorf("Execute() unexpected error: %v", err)
	}
	if exitCode != 1 {
		t.Errorf("Execute() exitCode = %v, want 1", exitCode)
	}
	if output != "No paths provided" {
		t.Errorf("Execute() output = %v, want 'No paths provided'", output)
	}
}

func TestFileHandler_Execute_DownloadUnknownType(t *testing.T) {
	handler := NewFileHandler(common.NewMockCommandExecutor(t), nil)
	ctx := context.Background()

	args := &common.CommandArgs{
		Username:  "testuser",
		Groupname: "testgroup",
		Path:      "/tmp/file.txt",
		Content:   "test content",
		Type:      "unknown_type",
	}

	exitCode, output, err := handler.Execute(ctx, "download", args)

	if err != nil {
		t.Errorf("Execute() unexpected error: %v", err)
	}
	if exitCode != 1 {
		t.Errorf("Execute() exitCode = %v, want 1", exitCode)
	}
	if output == "" {
		t.Error("Execute() expected error message in output")
	}
}

func TestFileExists(t *testing.T) {
	// Test with non-existent file
	if utils.FileExists("/nonexistent/path/file.txt") {
		t.Error("FileExists() should return false for non-existent file")
	}

	// Test with existing file (current file)
	if !utils.FileExists("file_test.go") {
		t.Error("FileExists() should return true for existing file")
	}
}

// TestFileUpload_UseBlob_OsFile_NoDoubleClose locks in the v2.1.6 regression
// where http.Client.Do auto-closes req.Body and fileUpload then calls
// src.Close() a second time. On *os.File the second Close returns
// os.ErrClosed, which fileUpload propagated as a failed upload. After the
// io.NopCloser wrap, http.Client.Do can no longer close src and our
// explicit Close is the single real close.
func TestFileUpload_UseBlob_OsFile_NoDoubleClose(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	tmpPath := filepath.Join(t.TempDir(), "blob.bin")
	if err := os.WriteFile(tmpPath, []byte("hello"), 0o600); err != nil {
		t.Fatalf("write temp: %v", err)
	}
	f, err := os.Open(tmpPath)
	if err != nil {
		t.Fatalf("open temp: %v", err)
	}

	h := NewFileHandler(common.NewMockCommandExecutor(t), nil)
	args := &common.CommandArgs{UseBlob: true, Content: srv.URL}

	code, err := h.fileUpload(args, f, 5, "blob.bin", false)
	if err != nil {
		t.Fatalf("fileUpload returned err=%v, want nil (regression of v2.1.6 double-close)", err)
	}
	if code != http.StatusOK {
		t.Errorf("fileUpload code=%d, want %d", code, http.StatusOK)
	}
}

// TestFileUpload_UseBlob_CloseErrorPropagates verifies the original intent
// of commit b9ba9712: when the underlying reader's Close() returns an
// error (e.g. demoted cat EACCES/ENOENT via cmdReadCloser), fileUpload
// must propagate it instead of reporting the upload as successful.
// closeCnt==1 also guards against a future regression that brings the
// double-close back.
func TestFileUpload_UseBlob_CloseErrorPropagates(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	closeSentinel := errors.New("synthetic close failure")
	er := &errReader{
		r:        strings.NewReader("hello"),
		failAt:   1 << 30,
		closeErr: closeSentinel,
	}

	h := NewFileHandler(common.NewMockCommandExecutor(t), nil)
	args := &common.CommandArgs{UseBlob: true, Content: srv.URL}

	_, err := h.fileUpload(args, er, 5, "blob.bin", false)
	if !errors.Is(err, closeSentinel) {
		t.Fatalf("fileUpload err=%v, want chain containing %v", err, closeSentinel)
	}
	if er.closeCnt != 1 {
		t.Errorf("errReader.Close was called %d time(s), want exactly 1 (double-close regression)", er.closeCnt)
	}
}

// TestFileUpload_UseBlob_PutErrorTakesPrecedence verifies the `err == nil &&`
// guard: when utils.Put itself fails (transport-level error), that error is
// returned instead of the src.Close() error. Without this guard a Close()
// failure would mask the real PUT failure.
func TestFileUpload_UseBlob_PutErrorTakesPrecedence(t *testing.T) {
	closeSentinel := errors.New("synthetic close failure")
	er := &errReader{
		r:        strings.NewReader("hello"),
		failAt:   1 << 30,
		closeErr: closeSentinel,
	}

	h := NewFileHandler(common.NewMockCommandExecutor(t), nil)
	// Bind to 127.0.0.1:0 to claim a free port, then close the listener so
	// any subsequent connection to that address is deterministically refused.
	// This avoids depending on a specific port (e.g. tcpmux/1) being closed
	// in CI/container environments.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	closedAddr := ln.Addr().String()
	_ = ln.Close()
	args := &common.CommandArgs{UseBlob: true, Content: "http://" + closedAddr + "/blob"}

	_, err = h.fileUpload(args, er, 5, "blob.bin", false)
	if err == nil {
		t.Fatal("fileUpload returned nil err, want PUT transport error")
	}
	if errors.Is(err, closeSentinel) {
		t.Errorf("fileUpload returned close error %v; PUT transport error should take precedence", err)
	}
}

func TestFileHandler_parsePaths(t *testing.T) {
	// This test uses Unix-style absolute paths ("/home/user", "/tmp/...").
	// On Windows those paths join with the supplied home into shapes
	// that filepath.IsAbs/Stat behave oddly on, so the cases here only
	// document the Unix contract. Windows-specific coverage lives in
	// file_windows_test.go (regression tests for #311).
	if runtime.GOOS == "windows" {
		t.Skip("Unix path conventions; Windows-specific coverage lives in file_windows_test.go")
	}
	handler := NewFileHandler(common.NewMockCommandExecutor(t), nil)

	tests := []struct {
		name          string
		homeDirectory string
		pathList      []string
		wantBulk      bool
		wantErr       bool
	}{
		{
			name:          "single absolute path",
			homeDirectory: "/home/user",
			pathList:      []string{"/tmp/file.txt"},
			wantBulk:      false,
			wantErr:       true, // File doesn't exist
		},
		{
			name:          "multiple paths",
			homeDirectory: "/home/user",
			pathList:      []string{"/tmp/file1.txt", "/tmp/file2.txt"},
			wantBulk:      true,
			wantErr:       false, // Bulk mode doesn't check file existence in parsePaths
		},
		{
			name:          "tilde path",
			homeDirectory: "/home/testuser",
			pathList:      []string{"~/file.txt"},
			wantBulk:      false,
			wantErr:       true, // File doesn't exist
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, bulk, _, err := handler.parsePaths(tt.homeDirectory, tt.pathList)

			if (err != nil) != tt.wantErr {
				t.Errorf("parsePaths() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err == nil && bulk != tt.wantBulk {
				t.Errorf("parsePaths() bulk = %v, want %v", bulk, tt.wantBulk)
			}
		})
	}
}
