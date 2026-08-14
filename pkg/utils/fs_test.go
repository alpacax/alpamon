package utils

import (
	"archive/zip"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFileExists(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "test_file_exists_*")
	require.NoError(t, err)
	tmpPath := tmpFile.Name()
	_ = tmpFile.Close()
	defer func() { _ = os.Remove(tmpPath) }()

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
		{
			name: "empty path returns false",
			path: "",
			want: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, FileExists(tc.path), "path %q", tc.path)
		})
	}
}

func TestCopyFile(t *testing.T) {
	srcFile, err := os.CreateTemp("", "test_copy_src_*")
	require.NoError(t, err)
	srcPath := srcFile.Name()
	defer func() { _ = os.Remove(srcPath) }()

	content := []byte("hello world")
	_, err = srcFile.Write(content)
	require.NoError(t, err)
	_ = srcFile.Close()

	require.NoError(t, os.Chmod(srcPath, 0644))

	t.Run("basic copy", func(t *testing.T) {
		dstPath := srcPath + "_copy"
		defer func() { _ = os.Remove(dstPath) }()

		require.NoError(t, CopyFile(srcPath, dstPath, true))

		got, err := os.ReadFile(dstPath)
		require.NoError(t, err)
		assert.Equal(t, string(content), string(got))

		srcInfo, err := os.Stat(srcPath)
		require.NoError(t, err)
		dstInfo, err := os.Stat(dstPath)
		require.NoError(t, err)
		assert.Equal(t, srcInfo.Mode(), dstInfo.Mode())
	})

	t.Run("non-existent source", func(t *testing.T) {
		assert.Error(t, CopyFile("/nonexistent/file", "/tmp/dst", true))
	})

	t.Run("non-existent destination directory", func(t *testing.T) {
		assert.Error(t, CopyFile(srcPath, "/nonexistent/dir/file", true))
	})
}

func TestCopyDir(t *testing.T) {
	srcDir, err := os.MkdirTemp("", "test_copydir_src_*")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(srcDir) }()

	require.NoError(t, os.WriteFile(filepath.Join(srcDir, "file1.txt"), []byte("one"), 0644))
	subDir := filepath.Join(srcDir, "subdir")
	require.NoError(t, os.Mkdir(subDir, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(subDir, "file2.txt"), []byte("two"), 0644))

	t.Run("basic directory copy", func(t *testing.T) {
		dstDir, err := os.MkdirTemp("", "test_copydir_dst_*")
		require.NoError(t, err)
		_ = os.RemoveAll(dstDir)
		defer func() { _ = os.RemoveAll(dstDir) }()

		require.NoError(t, CopyDir(srcDir, dstDir, false))

		got1, err := os.ReadFile(filepath.Join(dstDir, "file1.txt"))
		require.NoError(t, err, "file1.txt not copied")
		assert.Equal(t, "one", string(got1))

		got2, err := os.ReadFile(filepath.Join(dstDir, "subdir", "file2.txt"))
		require.NoError(t, err, "subdir/file2.txt not copied")
		assert.Equal(t, "two", string(got2))
	})

	t.Run("reject infinite recursion", func(t *testing.T) {
		dst := filepath.Join(srcDir, "inside")
		assert.Error(t, CopyDir(srcDir, dst, false))
	})

	t.Run("overwrite existing directory", func(t *testing.T) {
		dstDir, err := os.MkdirTemp("", "test_copydir_overwrite_*")
		require.NoError(t, err)
		defer func() { _ = os.RemoveAll(dstDir) }()

		// Create existing content that should be replaced
		require.NoError(t, os.WriteFile(filepath.Join(dstDir, "old.txt"), []byte("old"), 0644))

		require.NoError(t, CopyDir(srcDir, dstDir, true))

		// New content should exist
		got, err := os.ReadFile(filepath.Join(dstDir, "file1.txt"))
		require.NoError(t, err, "file1.txt not copied")
		assert.Equal(t, "one", string(got))

		// Old content should not exist
		_, err = os.Stat(filepath.Join(dstDir, "old.txt"))
		assert.ErrorIs(t, err, os.ErrNotExist, "old.txt should not exist after overwrite")
	})

	t.Run("non-existent source returns error", func(t *testing.T) {
		assert.Error(t, CopyDir("/nonexistent/source", "/tmp/dst", false))
	})
}

func TestGetCopyPath(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "test_getcopypath_*")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tmpDir) }()

	srcPath := filepath.Join(tmpDir, "file.txt")
	require.NoError(t, os.WriteFile(srcPath, []byte("test"), 0644))

	t.Run("generates numbered copy", func(t *testing.T) {
		assert.Equal(t, filepath.Join(tmpDir, "file (1).txt"), GetCopyPath(srcPath, srcPath))
	})

	t.Run("skips existing numbered copies", func(t *testing.T) {
		copy1 := filepath.Join(tmpDir, "file (1).txt")
		require.NoError(t, os.WriteFile(copy1, []byte("copy"), 0644))

		assert.Equal(t, filepath.Join(tmpDir, "file (2).txt"), GetCopyPath(srcPath, srcPath))
	})
}

func TestChownRecursive(t *testing.T) {
	t.Run("non-existent path returns error", func(t *testing.T) {
		assert.Error(t, ChownRecursive("/nonexistent/path", 1000, 1000))
	})
}

func makeZipFile(t *testing.T, path string) {
	t.Helper()
	f, err := os.Create(path)
	require.NoError(t, err)
	w := zip.NewWriter(f)
	_ = w.Close()
	_ = f.Close()
}

func TestOpenIfZip(t *testing.T) {
	tmpDir := t.TempDir()

	t.Run("valid zip returns handle", func(t *testing.T) {
		p := filepath.Join(tmpDir, "valid.zip")
		makeZipFile(t, p)
		rc := OpenIfZip(p, ".zip")
		require.NotNil(t, rc)
		_ = rc.Close()
	})

	tests := []struct {
		name  string
		file  string
		ext   string
		isZip bool
	}{
		{
			name: "non-zip file returns nil",
			file: "plain.txt",
			ext:  ".txt",
		},
		{
			name:  "denylisted extension returns nil",
			file:  "lib.jar",
			ext:   ".jar",
			isZip: true,
		},
		{
			name:  "uppercase denylisted extension returns nil",
			file:  "lib.JAR",
			ext:   ".JAR",
			isZip: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := filepath.Join(tmpDir, tc.file)
			if tc.isZip {
				makeZipFile(t, p)
			} else {
				require.NoError(t, os.WriteFile(p, []byte("hello"), 0644))
			}

			if rc := OpenIfZip(p, tc.ext); !assert.Nil(t, rc) {
				_ = rc.Close()
			}
		})
	}
}
