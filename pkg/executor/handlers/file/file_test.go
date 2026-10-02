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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
			assert.Equal(t, tt.wantErr, err != nil, "Validate() error = %v", err)
		})
	}
}

func TestFileHandler_Execute_UnknownCommand(t *testing.T) {
	handler := NewFileHandler(common.NewMockCommandExecutor(t), nil)
	ctx := context.Background()

	exitCode, _, err := handler.Execute(ctx, "unknown", &common.CommandArgs{})

	assert.Error(t, err, "Execute() expected error for unknown command")
	assert.Equal(t, 1, exitCode)
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

	assert.NoError(t, err)
	assert.Equal(t, 1, exitCode)
	assert.Equal(t, "No paths provided", output)
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

	assert.NoError(t, err)
	assert.Equal(t, 1, exitCode)
	assert.NotEmpty(t, output, "Execute() expected error message in output")
}

func TestFileExists(t *testing.T) {
	// Test with non-existent file
	assert.False(t, utils.FileExists("/nonexistent/path/file.txt"), "FileExists() should return false for non-existent file")

	// Test with existing file (current file)
	assert.True(t, utils.FileExists("file_test.go"), "FileExists() should return true for existing file")
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
	require.NoError(t, os.WriteFile(tmpPath, []byte("hello"), 0o600), "write temp")
	f, err := os.Open(tmpPath)
	require.NoError(t, err, "open temp")

	h := NewFileHandler(common.NewMockCommandExecutor(t), nil)
	args := &common.CommandArgs{UseBlob: true, Content: srv.URL}

	code, err := h.fileUpload(args, f, 5, "blob.bin", false)
	require.NoError(t, err, "fileUpload want nil (regression of v2.1.6 double-close)")
	assert.Equal(t, http.StatusOK, code, "fileUpload code")
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
	require.ErrorIs(t, err, closeSentinel, "fileUpload err want chain containing sentinel")
	assert.Equal(t, 1, er.closeCnt, "errReader.Close call count, want exactly 1 (double-close regression)")
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
	require.Error(t, err, "fileUpload returned nil err, want PUT transport error")
	assert.NotErrorIs(t, err, closeSentinel, "PUT transport error should take precedence over close error")
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

			assert.Equal(t, tt.wantErr, err != nil, "parsePaths() error = %v", err)
			if err == nil {
				assert.Equal(t, tt.wantBulk, bulk, "parsePaths() bulk")
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
			assert.Equal(t, tt.want, isStagePath(tt.path), "isStagePath(%q)", tt.path)
		})
	}
}

// TestRemoveStaged exercises rm -f semantics in isolation from the staging-path guard.
func TestRemoveStaged(t *testing.T) {
	t.Run("existing file removed", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "staged.sh")
		require.NoError(t, os.WriteFile(path, []byte("#!/bin/sh\n"), 0o600), "write temp")

		code, _ := removeStaged(path)
		assert.Equal(t, 0, code, "removeStaged() code")
		assert.False(t, utils.FileExists(path), "removeStaged() left the file in place")
	})

	t.Run("missing file treated as success", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "missing.sh")

		code, message := removeStaged(path)
		assert.Equal(t, 0, code, "removeStaged() code")
		assert.NotEmpty(t, message, "removeStaged() expected a message for the missing-file case")
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
		if runtime.GOOS == "windows" {
			t.Skip("handleRm refuses on Windows (POSIX-only staging contract)")
		}
		args := &common.CommandArgs{Path: "/tmp/.alpacon-exec-deadbeefcafe.sh"}

		exitCode, _, err := handler.Execute(ctx, "rm", args)
		assert.NoError(t, err)
		assert.Equal(t, 0, exitCode)
	})

	t.Run("refused on Windows", func(t *testing.T) {
		if runtime.GOOS != "windows" {
			t.Skip("Windows-only staging refusal")
		}
		exitCode, output, err := handler.Execute(ctx, "rm", &common.CommandArgs{Path: "/tmp/.alpacon-exec-deadbeefcafe.sh"})
		assert.NoError(t, err)
		assert.Equal(t, 1, exitCode)
		assert.NotEmpty(t, output, "Execute() expected a platform-refusal message")
	})

	nonStagePaths := []string{
		"/etc/passwd",
		"/tmp/evil.sh",
		"/tmp/../etc/x",
	}
	for _, path := range nonStagePaths {
		t.Run("rejected: "+path, func(t *testing.T) {
			exitCode, output, err := handler.Execute(ctx, "rm", &common.CommandArgs{Path: path})
			assert.NoError(t, err)
			assert.Equal(t, 1, exitCode)
			assert.NotEmpty(t, output, "Execute() expected a rejection message")
		})
	}
}

// TestFileHandler_Execute_EscapesTheResult uses rm, which echoes the path back raw.
func TestFileHandler_Execute_EscapesTheResult(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("handleRm refuses on Windows before it names the path")
	}
	handler := NewFileHandler(common.NewMockCommandExecutor(t), nil)

	exitCode, output, err := handler.Execute(context.Background(), "rm",
		&common.CommandArgs{Path: "/tmp/evil\x9b[2J.sh"})

	require.NoError(t, err)
	assert.Equal(t, 1, exitCode)
	assert.Contains(t, output, `/tmp/evil\x9b[2J.sh`)
	assert.NotContains(t, output, "\x9b")
}

func TestUploadSummary(t *testing.T) {
	skip := func(path, reason string) utils.SkippedEntry {
		return utils.SkippedEntry{Path: path, Reason: errors.New(reason)}
	}

	report := func(entries ...utils.SkippedEntry) utils.SkippedReport {
		return utils.SkippedReport{Entries: entries, Total: len(entries)}
	}

	tests := []struct {
		name    string
		count   int
		skipped utils.SkippedReport
		want    string
	}{
		{
			name:  "nothing skipped reads as before",
			count: 3,
			want:  "Successfully uploaded 3 file(s).",
		},
		{
			name:    "a skipped path replaces the success count with its cause",
			count:   2,
			skipped: report(skip("/home/u/secret.txt", "permission denied")),
			want:    "Uploaded the archive, skipping 1 path(s): /home/u/secret.txt: permission denied",
		},
		{
			name:  "the tail collapses into a count",
			count: 1,
			skipped: report(
				skip("/a", "permission denied"),
				skip("/b", "permission denied"),
				skip("/c", "permission denied"),
				skip("/d", "no such file or directory"),
				skip("/e", "input/output error"),
			),
			want: "Uploaded the archive, skipping 5 path(s): " +
				"/a: permission denied; /b: permission denied; /c: permission denied; and 2 more",
		},
		{
			// The worker caps the list it sends but not the count.
			name:  "a bounded list still reports the true total",
			count: 1,
			skipped: utils.SkippedReport{
				Entries: []utils.SkippedEntry{
					skip("/a", "permission denied"),
					skip("/b", "permission denied"),
				},
				Total: 137,
			},
			want: "Uploaded the archive, skipping 137 path(s): " +
				"/a: permission denied; /b: permission denied; and 135 more",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, uploadSummary(tt.count, tt.skipped))
		})
	}
}
