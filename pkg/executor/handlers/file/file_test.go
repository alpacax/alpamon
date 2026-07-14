package file

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/alpacax/alpamon/v2/pkg/executor/handlers/common"
	"github.com/alpacax/alpamon/v2/pkg/utils"
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
			name: "rm valid",
			cmd:  "rm",
			args: &common.CommandArgs{
				Path: "/tmp/.alpacon-exec-deadbeef.sh",
			},
			wantErr: false,
		},
		{
			name:    "rm missing path",
			cmd:     "rm",
			args:    &common.CommandArgs{},
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
	// Port 0 is reserved and cannot be dialed; net.Dial fails immediately
	// with "can't assign requested address" / "invalid argument", giving a
	// deterministic transport-level error without depending on any port
	// being closed or claiming an ephemeral port that could be re-bound
	// in the window between listener close and the PUT attempt.
	args := &common.CommandArgs{UseBlob: true, Content: "http://127.0.0.1:0/blob"}

	_, err := h.fileUpload(args, er, 5, "blob.bin", false)
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

// TestIsStagePath locks in the unsigned-rm security guard (see stagedExecScriptPattern).
func TestIsStagePath(t *testing.T) {
	tests := []struct {
		name string
		path string
		want bool
	}{
		{
			name: "valid staged path",
			path: "/tmp/.alpacon-exec-deadbeef.sh",
			want: true,
		},
		{
			name: "valid staged path single hex digit",
			path: "/tmp/.alpacon-exec-a.sh",
			want: true,
		},
		{
			name: "non-stage absolute path",
			path: "/etc/passwd",
			want: false,
		},
		{
			name: "tmp path but wrong name",
			path: "/tmp/evil.sh",
			want: false,
		},
		{
			name: "traversal out of tmp",
			path: "/tmp/../etc/x",
			want: false,
		},
		{
			name: "traversal folded back into staged name",
			path: "/tmp/foo/../.alpacon-exec-deadbeef.sh",
			want: true,
		},
		{
			name: "uppercase hex rejected",
			path: "/tmp/.alpacon-exec-DEADBEEF.sh",
			want: false,
		},
		{
			name: "empty hex rejected",
			path: "/tmp/.alpacon-exec-.sh",
			want: false,
		},
		{
			name: "empty path",
			path: "",
			want: false,
		},
		// Go's default (?-m) $ anchors to end-of-text only, so a trailing
		// newline/CR must not pass. Locks that in against a future (?m).
		{
			name: "trailing newline rejected",
			path: "/tmp/.alpacon-exec-deadbeef.sh\n",
			want: false,
		},
		{
			name: "trailing crlf rejected",
			path: "/tmp/.alpacon-exec-deadbeef.sh\r\n",
			want: false,
		},
		{
			name: "trailing cr rejected",
			path: "/tmp/.alpacon-exec-deadbeef.sh\r",
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isStagePath(tt.path); got != tt.want {
				t.Errorf("isStagePath(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

// TestRemoveStaged exercises rm -f semantics in isolation from the staging-path guard.
func TestRemoveStaged(t *testing.T) {
	t.Run("existing file removed", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "staged.sh")
		if err := os.WriteFile(path, []byte("#!/bin/sh\n"), 0o600); err != nil {
			t.Fatalf("write temp: %v", err)
		}

		code, _ := removeStaged(path)
		if code != 0 {
			t.Errorf("removeStaged() code = %v, want 0", code)
		}
		if utils.FileExists(path) {
			t.Error("removeStaged() left the file in place")
		}
	})

	t.Run("missing file treated as success", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "missing.sh")

		code, message := removeStaged(path)
		if code != 0 {
			t.Errorf("removeStaged() code = %v, want 0", code)
		}
		if message == "" {
			t.Error("removeStaged() expected a message for the missing-file case")
		}
	})
}

// TestFileHandler_Execute_Rm covers the wiring from Execute through to
// handleRm. It only drives the missing-file branch: a real staged path
// under /tmp cannot be created safely from a portable test, and the
// guard/removal logic already have dedicated coverage above.
func TestFileHandler_Execute_Rm(t *testing.T) {
	handler := NewFileHandler(common.NewMockCommandExecutor(t), nil)
	ctx := context.Background()

	t.Run("valid staged path, file missing", func(t *testing.T) {
		args := &common.CommandArgs{Path: "/tmp/.alpacon-exec-deadbeefcafe.sh"}

		exitCode, _, err := handler.Execute(ctx, "rm", args)
		if err != nil {
			t.Errorf("Execute() unexpected error: %v", err)
		}
		if exitCode != 0 {
			t.Errorf("Execute() exitCode = %v, want 0", exitCode)
		}
	})

	nonStagePaths := []string{
		"/etc/passwd",
		"/tmp/evil.sh",
		"/tmp/../etc/x",
	}
	for _, path := range nonStagePaths {
		t.Run("rejected: "+path, func(t *testing.T) {
			exitCode, output, err := handler.Execute(ctx, "rm", &common.CommandArgs{Path: path})
			if err != nil {
				t.Errorf("Execute() unexpected error: %v", err)
			}
			if exitCode != 1 {
				t.Errorf("Execute() exitCode = %v, want 1", exitCode)
			}
			if output == "" {
				t.Error("Execute() expected a rejection message")
			}
		})
	}
}
