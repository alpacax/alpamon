package file

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/alpacax/alpamon/pkg/config"
	"github.com/alpacax/alpamon/pkg/executor/handlers/common"
	"github.com/alpacax/alpamon/pkg/utils"
)

type trackingReadCloser struct {
	closed bool
}

func (r *trackingReadCloser) Read(_ []byte) (int, error) {
	return 0, io.EOF
}

func (r *trackingReadCloser) Close() error {
	r.closed = true
	return nil
}

type partialErrorReader struct {
	payload []byte
	sent    bool
}

func (r *partialErrorReader) Read(p []byte) (int, error) {
	if !r.sent {
		r.sent = true
		n := copy(p, r.payload)
		return n, nil
	}
	return 0, errors.New("forced stream error")
}

type failingAPISession struct {
	err error
}

func (s *failingAPISession) MultipartRequest(_ string, _ io.Reader, _ string, _ int64, _ time.Duration) ([]byte, int, error) {
	if s.err == nil {
		return nil, 0, errors.New("upload failed")
	}
	return nil, 0, s.err
}

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

func TestFileHandler_fileUpload_ClosesBodyWhenAPISessionMissing(t *testing.T) {
	handler := &FileHandler{}
	body := &trackingReadCloser{}

	_, _, err := handler.fileUpload("https://example.com/upload", false, body, "multipart/form-data", -1)
	if err == nil {
		t.Fatal("fileUpload() expected error when API session is missing")
	}
	if !body.closed {
		t.Fatal("fileUpload() should close body when API session is missing")
	}
}

func TestFileHandler_fileUpload_ClosesBodyWhenMultipartRequestFails(t *testing.T) {
	handler := &FileHandler{
		apiSession: &failingAPISession{err: errors.New("request failed")},
	}
	body := &trackingReadCloser{}

	_, _, err := handler.fileUpload("https://example.com/upload", false, body, "multipart/form-data", -1)
	if err == nil {
		t.Fatal("fileUpload() expected error")
	}
	if !body.closed {
		t.Fatal("fileUpload() should close body when multipart request fails")
	}
}

func TestFileHandler_fileUpload_ClosesBodyWhenBlobPutFails(t *testing.T) {
	handler := &FileHandler{}
	body := &trackingReadCloser{}

	_, _, err := handler.fileUpload("://invalid-url", true, body, "", -1)
	if err == nil {
		t.Fatal("fileUpload() expected error")
	}
	if !body.closed {
		t.Fatal("fileUpload() should close body when blob upload fails")
	}
}

func TestMultipartBufferThresholdBytes_UsesDefaultWhenUnset(t *testing.T) {
	prev := config.GlobalSettings.UploadBufferMB
	config.GlobalSettings.UploadBufferMB = 0
	t.Cleanup(func() {
		config.GlobalSettings.UploadBufferMB = prev
	})

	got := multipartBufferThresholdBytes()
	want := int64(config.DefaultUploadBufferMB * 1024 * 1024)
	if got != want {
		t.Fatalf("multipartBufferThresholdBytes() = %d, want %d", got, want)
	}
}

func TestShouldUseMultipartBuffer(t *testing.T) {
	tests := []struct {
		name          string
		contentSize   int64
		thresholdSize int64
		want          bool
	}{
		{
			name:          "use buffer when content fits threshold",
			contentSize:   8 * 1024 * 1024,
			thresholdSize: 16 * 1024 * 1024,
			want:          true,
		},
		{
			name:          "stream when content is larger than threshold",
			contentSize:   32 * 1024 * 1024,
			thresholdSize: 16 * 1024 * 1024,
			want:          false,
		},
		{
			name:          "stream when threshold is invalid",
			contentSize:   8 * 1024 * 1024,
			thresholdSize: 0,
			want:          false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := shouldUseMultipartBuffer(tt.contentSize, tt.thresholdSize)
			if got != tt.want {
				t.Fatalf("shouldUseMultipartBuffer() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMultipartFallbackBufferLimitBytes(t *testing.T) {
	defaultLimit := int64(64 * 1024 * 1024)
	largeThreshold := int64(128 * 1024 * 1024)

	if got := multipartFallbackBufferLimitBytes(16 * 1024 * 1024); got != defaultLimit {
		t.Fatalf("multipartFallbackBufferLimitBytes() = %d, want %d", got, defaultLimit)
	}
	if got := multipartFallbackBufferLimitBytes(largeThreshold); got != largeThreshold {
		t.Fatalf("multipartFallbackBufferLimitBytes() = %d, want %d", got, largeThreshold)
	}
}

func TestShouldFallbackToBufferedMultipart(t *testing.T) {
	threshold := int64(16 * 1024 * 1024)

	if !shouldFallbackToBufferedMultipart(32*1024*1024, threshold) {
		t.Fatal("shouldFallbackToBufferedMultipart() should allow fallback when file size is under fallback limit")
	}
	if shouldFallbackToBufferedMultipart(128*1024*1024, threshold) {
		t.Fatal("shouldFallbackToBufferedMultipart() should block fallback when file size exceeds fallback limit")
	}
	if shouldFallbackToBufferedMultipart(-1, threshold) {
		t.Fatal("shouldFallbackToBufferedMultipart() should block fallback for unknown file sizes")
	}
}

func TestWriteDownloadContentAtomically_WritesFinalFile(t *testing.T) {
	handler := &FileHandler{}
	targetDir := t.TempDir()
	targetPath := filepath.Join(targetDir, "downloaded.txt")
	payload := []byte("hello-download")

	err := handler.writeDownloadContentAtomically(targetPath, bytes.NewReader(payload), nil)
	if err != nil {
		t.Fatalf("writeDownloadContentAtomically() unexpected error: %v", err)
	}

	content, err := os.ReadFile(targetPath)
	if err != nil {
		t.Fatalf("failed to read final downloaded file: %v", err)
	}
	if !bytes.Equal(content, payload) {
		t.Fatalf("final file content mismatch: got %q, want %q", string(content), string(payload))
	}
}

func TestWriteDownloadContentAtomically_CleansPartialOnError(t *testing.T) {
	handler := &FileHandler{}
	targetDir := t.TempDir()
	targetPath := filepath.Join(targetDir, "downloaded.txt")

	err := handler.writeDownloadContentAtomically(targetPath, &partialErrorReader{
		payload: bytes.Repeat([]byte("a"), 1024),
	}, nil)
	if err == nil {
		t.Fatal("writeDownloadContentAtomically() expected error on broken input stream")
	}

	if _, statErr := os.Stat(targetPath); !os.IsNotExist(statErr) {
		t.Fatalf("final file should not remain on failure, statErr=%v", statErr)
	}

	entries, readDirErr := os.ReadDir(targetDir)
	if readDirErr != nil {
		t.Fatalf("failed to read temp directory: %v", readDirErr)
	}
	if len(entries) != 0 {
		t.Fatalf("temporary files should be cleaned up on failure, remaining entries=%d", len(entries))
	}
}

func TestIsZipFile(t *testing.T) {
	tests := []struct {
		name    string
		content []byte
		ext     string
		want    bool
	}{
		{
			name:    "jar file extension",
			content: []byte("PK\x03\x04"), // zip magic bytes
			ext:     ".jar",
			want:    false, // Should be excluded
		},
		{
			name:    "war file extension",
			content: []byte("PK\x03\x04"),
			ext:     ".war",
			want:    false, // Should be excluded
		},
		{
			name:    "regular zip content",
			content: []byte("PK\x03\x04"),
			ext:     ".zip",
			want:    false, // Invalid zip (too short)
		},
		{
			name:    "non-zip content",
			content: []byte("hello world"),
			ext:     ".txt",
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := utils.IsZipFile(tt.content, tt.ext)
			if got != tt.want {
				t.Errorf("IsZipFile() = %v, want %v", got, tt.want)
			}
		})
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

func TestFileHandler_parsePaths(t *testing.T) {
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

func TestNonZipExtensions(t *testing.T) {
	// Test that zip-like extensions are excluded from IsZipFile
	zipContent := []byte("PK\x03\x04") // zip magic bytes (but invalid/short)
	excludedExtensions := []string{
		".jar", ".war", ".ear", ".apk", ".xpi",
		".vsix", ".crx", ".egg", ".whl", ".appx",
		".msix", ".ipk", ".nupkg", ".kmz",
	}

	for _, ext := range excludedExtensions {
		if utils.IsZipFile(zipContent, ext) {
			t.Errorf("Expected extension %s to be excluded from IsZipFile", ext)
		}
	}
}
