package utils

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFileExists(t *testing.T) {
	// Create a temp file
	tmpFile, err := os.CreateTemp("", "test_file_exists_*")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	tmpPath := tmpFile.Name()
	_ = tmpFile.Close()
	defer os.Remove(tmpPath)

	tests := []struct {
		name string
		path string
		want bool
	}{
		{
			name: "existing file",
			path: tmpPath,
			want: true,
		},
		{
			name: "non-existent file",
			path: "/nonexistent/path/file.txt",
			want: false,
		},
		{
			name: "existing directory",
			path: os.TempDir(),
			want: true,
		},
		{
			name: "path with dot-dot is resolved",
			path: filepath.Join(os.TempDir(), "..", filepath.Base(os.TempDir())),
			want: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := FileExists(tc.path)
			if got != tc.want {
				t.Fatalf("FileExists(%q) = %v, want %v", tc.path, got, tc.want)
			}
		})
	}
}

func TestCopyFile(t *testing.T) {
	// Create source file with content
	srcFile, err := os.CreateTemp("", "test_copy_src_*")
	if err != nil {
		t.Fatalf("failed to create source file: %v", err)
	}
	srcPath := srcFile.Name()
	defer os.Remove(srcPath)

	content := []byte("hello world")
	if _, err := srcFile.Write(content); err != nil {
		t.Fatalf("failed to write source: %v", err)
	}
	_ = srcFile.Close()

	// Set specific permissions
	if err := os.Chmod(srcPath, 0644); err != nil {
		t.Fatalf("failed to chmod source: %v", err)
	}

	t.Run("basic copy", func(t *testing.T) {
		dstPath := srcPath + "_copy"
		defer os.Remove(dstPath)

		err := CopyFile(srcPath, dstPath, true)
		if err != nil {
			t.Fatalf("CopyFile() error: %v", err)
		}

		// Verify content
		got, err := os.ReadFile(dstPath)
		if err != nil {
			t.Fatalf("failed to read dst: %v", err)
		}
		if string(got) != string(content) {
			t.Fatalf("CopyFile() content = %q, want %q", got, content)
		}

		// Verify permissions
		srcInfo, _ := os.Stat(srcPath)
		dstInfo, _ := os.Stat(dstPath)
		if srcInfo.Mode() != dstInfo.Mode() {
			t.Fatalf("CopyFile() mode = %v, want %v", dstInfo.Mode(), srcInfo.Mode())
		}
	})

	t.Run("non-existent source", func(t *testing.T) {
		err := CopyFile("/nonexistent/file", "/tmp/dst", true)
		if err == nil {
			t.Fatal("CopyFile() expected error for non-existent source")
		}
	})
}

func TestCopyDir(t *testing.T) {
	// Create source directory structure
	srcDir, err := os.MkdirTemp("", "test_copydir_src_*")
	if err != nil {
		t.Fatalf("failed to create source dir: %v", err)
	}
	defer os.RemoveAll(srcDir)

	// Create files in source
	if err := os.WriteFile(filepath.Join(srcDir, "file1.txt"), []byte("one"), 0644); err != nil {
		t.Fatalf("failed to create file1: %v", err)
	}
	subDir := filepath.Join(srcDir, "subdir")
	if err := os.Mkdir(subDir, 0755); err != nil {
		t.Fatalf("failed to create subdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(subDir, "file2.txt"), []byte("two"), 0644); err != nil {
		t.Fatalf("failed to create file2: %v", err)
	}

	t.Run("basic directory copy", func(t *testing.T) {
		dstDir, err := os.MkdirTemp("", "test_copydir_dst_*")
		if err != nil {
			t.Fatalf("failed to create dst dir: %v", err)
		}
		os.RemoveAll(dstDir) // CopyDir creates it
		defer os.RemoveAll(dstDir)

		err = CopyDir(srcDir, dstDir, false)
		if err != nil {
			t.Fatalf("CopyDir() error: %v", err)
		}

		// Verify files exist
		got1, err := os.ReadFile(filepath.Join(dstDir, "file1.txt"))
		if err != nil {
			t.Fatalf("file1.txt not copied: %v", err)
		}
		if string(got1) != "one" {
			t.Fatalf("file1.txt content = %q, want %q", got1, "one")
		}

		got2, err := os.ReadFile(filepath.Join(dstDir, "subdir", "file2.txt"))
		if err != nil {
			t.Fatalf("subdir/file2.txt not copied: %v", err)
		}
		if string(got2) != "two" {
			t.Fatalf("subdir/file2.txt content = %q, want %q", got2, "two")
		}
	})

	t.Run("reject infinite recursion", func(t *testing.T) {
		dst := filepath.Join(srcDir, "inside")
		err := CopyDir(srcDir, dst, false)
		if err == nil {
			t.Fatal("CopyDir() expected error for dst inside src")
		}
	})
}

func TestGetCopyPath(t *testing.T) {
	// Create a temp directory for test
	tmpDir, err := os.MkdirTemp("", "test_getcopypath_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create existing file
	srcPath := filepath.Join(tmpDir, "file.txt")
	if err := os.WriteFile(srcPath, []byte("test"), 0644); err != nil {
		t.Fatalf("failed to create file: %v", err)
	}

	t.Run("generates numbered copy", func(t *testing.T) {
		got := GetCopyPath(srcPath, srcPath)
		expected := filepath.Join(tmpDir, "file (1).txt")
		if got != expected {
			t.Fatalf("GetCopyPath() = %q, want %q", got, expected)
		}
	})

	t.Run("skips existing numbered copies", func(t *testing.T) {
		// Create file (1).txt
		copy1 := filepath.Join(tmpDir, "file (1).txt")
		if err := os.WriteFile(copy1, []byte("copy"), 0644); err != nil {
			t.Fatalf("failed to create copy: %v", err)
		}

		got := GetCopyPath(srcPath, srcPath)
		expected := filepath.Join(tmpDir, "file (2).txt")
		if got != expected {
			t.Fatalf("GetCopyPath() = %q, want %q", got, expected)
		}
	})
}

func TestChownRecursive(t *testing.T) {
	// ChownRecursive requires root, so just verify it handles non-existent paths
	t.Run("non-existent path returns error", func(t *testing.T) {
		err := ChownRecursive("/nonexistent/path", 1000, 1000)
		if err == nil {
			t.Fatal("ChownRecursive() expected error for non-existent path")
		}
	})
}
