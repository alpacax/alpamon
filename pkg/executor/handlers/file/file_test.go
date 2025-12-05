package file

import (
	"context"
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
