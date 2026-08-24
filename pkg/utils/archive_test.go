package utils

import (
	"archive/zip"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// writeZip builds a zip at path with one entry per name/content pair. A nil
// map produces an empty zip.
func writeZip(t *testing.T, path string, entries map[string]string) {
	t.Helper()
	f, err := os.Create(path)
	require.NoError(t, err)
	w := zip.NewWriter(f)
	for name, content := range entries {
		zw, err := w.Create(name)
		require.NoError(t, err)
		_, err = zw.Write([]byte(content))
		require.NoError(t, err)
	}
	require.NoError(t, w.Close())
	require.NoError(t, f.Close())
}

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

func readZipEntry(t *testing.T, f *zip.File) string {
	t.Helper()
	rc, err := f.Open()
	require.NoError(t, err)
	body, err := io.ReadAll(rc)
	require.NoError(t, rc.Close())
	require.NoError(t, err)
	return string(body)
}

func TestCreateZip_SymlinksStoredAsEntries(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix-specific behavior")
	}

	dir := t.TempDir()
	realDir := filepath.Join(dir, "demo", "real")
	require.NoError(t, os.MkdirAll(realDir, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(realDir, "file.txt"), []byte("hi"), 0644))
	require.NoError(t, os.Symlink("real", filepath.Join(dir, "demo", "link")))
	require.NoError(t, os.Symlink("real/file.txt", filepath.Join(dir, "demo", "filelink")))
	require.NoError(t, os.Symlink(".", filepath.Join(dir, "demo", "loop")))

	dest := filepath.Join(dir, "out.zip")
	require.NoError(t, CreateZip(dest, []string{filepath.Join(dir, "demo")}, true))

	r, err := zip.OpenReader(dest)
	require.NoError(t, err)
	defer func() { _ = r.Close() }()

	entries := make(map[string]*zip.File, len(r.File))
	for _, f := range r.File {
		entries[f.Name] = f
	}

	// One real file plus the three links: following any link would add
	// duplicates or recurse into loop. Assert on r.File as well, because the
	// map collapses a name written twice into one key.
	require.Len(t, r.File, 4)
	require.Len(t, entries, 4, "archive holds duplicate entry names")
	require.Contains(t, entries, "demo/real/file.txt")
	for name, target := range map[string]string{
		"demo/link":     "real",
		"demo/filelink": "real/file.txt",
		"demo/loop":     ".",
	} {
		entry, ok := entries[name]
		require.True(t, ok, "link entry %s missing from archive", name)
		assert.NotZero(t, entry.Mode()&os.ModeSymlink, name)
		assert.Equal(t, target, readZipEntry(t, entry), name)
	}
}

func TestCreateZip_SymlinkedRootIsFollowed(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix-specific behavior")
	}

	dir := t.TempDir()
	realDir := filepath.Join(dir, "real")
	require.NoError(t, os.MkdirAll(realDir, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(realDir, "file.txt"), []byte("hi"), 0644))
	require.NoError(t, os.Symlink("real", filepath.Join(dir, "link")))

	dest := filepath.Join(dir, "out.zip")
	require.NoError(t, CreateZip(dest, []string{filepath.Join(dir, "link")}, true))

	r, err := zip.OpenReader(dest)
	require.NoError(t, err)
	defer func() { _ = r.Close() }()

	require.Len(t, r.File, 1)
	assert.Equal(t, "link/file.txt", r.File[0].Name)
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

	zipPath := filepath.Join(dir, "test.zip")
	writeZip(t, zipPath, map[string]string{
		"root.txt":       "root",
		"sub/nested.txt": "nested",
	})

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

	zipPath := filepath.Join(dir, "evil.zip")
	writeZip(t, zipPath, map[string]string{"../../etc/passwd": "malicious"})

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
