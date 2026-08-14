package utils

import (
	"archive/zip"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCreateZip_SingleFile(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "hello.txt")
	require.NoError(t, os.WriteFile(src, []byte("hello world"), 0644))

	dest := filepath.Join(dir, "out.zip")
	require.NoError(t, CreateZip(dest, []string{src}, false))

	r, err := zip.OpenReader(dest)
	require.NoError(t, err)
	defer func() { _ = r.Close() }()

	require.Len(t, r.File, 1)
	assert.Equal(t, "hello.txt", r.File[0].Name)
}

func TestCreateZip_RecursiveDirectory(t *testing.T) {
	dir := t.TempDir()
	subdir := filepath.Join(dir, "mydir", "sub")
	require.NoError(t, os.MkdirAll(subdir, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "mydir", "a.txt"), []byte("a"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(subdir, "b.txt"), []byte("b"), 0644))

	dest := filepath.Join(dir, "out.zip")
	require.NoError(t, CreateZip(dest, []string{filepath.Join(dir, "mydir")}, true))

	r, err := zip.OpenReader(dest)
	require.NoError(t, err)
	defer func() { _ = r.Close() }()

	assert.Len(t, r.File, 2)
}

func TestCreateZip_BulkMultiplePaths(t *testing.T) {
	dir := t.TempDir()
	f1 := filepath.Join(dir, "one.txt")
	f2 := filepath.Join(dir, "two.txt")
	require.NoError(t, os.WriteFile(f1, []byte("1"), 0644))
	require.NoError(t, os.WriteFile(f2, []byte("2"), 0644))

	dest := filepath.Join(dir, "out.zip")
	require.NoError(t, CreateZip(dest, []string{f1, f2}, true))

	r, err := zip.OpenReader(dest)
	require.NoError(t, err)
	defer func() { _ = r.Close() }()

	assert.Len(t, r.File, 2)
}

func TestUnzip(t *testing.T) {
	dir := t.TempDir()

	// Create a zip with a file and subdirectory
	zipPath := filepath.Join(dir, "test.zip")
	f, err := os.Create(zipPath)
	require.NoError(t, err)
	w := zip.NewWriter(f)
	zw, _ := w.Create("root.txt")
	_, _ = zw.Write([]byte("root"))
	zw, _ = w.Create("sub/nested.txt")
	_, _ = zw.Write([]byte("nested"))
	_ = w.Close()
	_ = f.Close()

	extractDir := filepath.Join(dir, "out")
	require.NoError(t, os.MkdirAll(extractDir, 0755))

	require.NoError(t, Unzip(zipPath, extractDir))

	content, err := os.ReadFile(filepath.Join(extractDir, "root.txt"))
	require.NoError(t, err)
	assert.Equal(t, "root", string(content))

	content, err = os.ReadFile(filepath.Join(extractDir, "sub", "nested.txt"))
	require.NoError(t, err)
	assert.Equal(t, "nested", string(content))
}

func TestUnzip_ZipSlipRejected(t *testing.T) {
	dir := t.TempDir()

	// Create a malicious zip with path traversal
	zipPath := filepath.Join(dir, "evil.zip")
	f, err := os.Create(zipPath)
	require.NoError(t, err)
	w := zip.NewWriter(f)
	zw, _ := w.Create("../../etc/passwd")
	_, _ = zw.Write([]byte("malicious"))
	_ = w.Close()
	_ = f.Close()

	extractDir := filepath.Join(dir, "out")
	require.NoError(t, os.MkdirAll(extractDir, 0755))

	assert.ErrorContains(t, Unzip(zipPath, extractDir), "illegal file path in zip")
}

func TestCreateZipAndUnzip_RoundTrip(t *testing.T) {
	dir := t.TempDir()

	// Create source files
	srcDir := filepath.Join(dir, "src")
	require.NoError(t, os.MkdirAll(filepath.Join(srcDir, "sub"), 0755))
	require.NoError(t, os.WriteFile(filepath.Join(srcDir, "a.txt"), []byte("aaa"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(srcDir, "sub", "b.txt"), []byte("bbb"), 0644))

	// Zip
	zipPath := filepath.Join(dir, "archive.zip")
	require.NoError(t, CreateZip(zipPath, []string{srcDir}, true))

	// Unzip
	outDir := filepath.Join(dir, "out")
	require.NoError(t, os.MkdirAll(outDir, 0755))
	require.NoError(t, Unzip(zipPath, outDir))

	// Verify round-trip
	content, err := os.ReadFile(filepath.Join(outDir, "src", "a.txt"))
	require.NoError(t, err, "a.txt not found after round-trip")
	assert.Equal(t, "aaa", string(content))

	content, err = os.ReadFile(filepath.Join(outDir, "src", "sub", "b.txt"))
	require.NoError(t, err, "sub/b.txt not found after round-trip")
	assert.Equal(t, "bbb", string(content))
}
