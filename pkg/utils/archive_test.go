package utils

import (
	"archive/zip"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

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

// requireZip builds the archive and requires that nothing was left out of it,
// so a test that does not care about skipping still fails if an entry silently
// goes missing.
func requireZip(t *testing.T, dest string, paths []string, recursive bool) {
	t.Helper()
	skipped, err := CreateZip(dest, paths, recursive)
	require.NoError(t, err)
	require.Empty(t, skipped)
}

func TestCreateZip_SingleFile(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "hello.txt")
	require.NoError(t, os.WriteFile(src, []byte("hello world"), 0644))

	dest := filepath.Join(dir, "out.zip")
	requireZip(t, dest, []string{src}, false)

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
	requireZip(t, dest, []string{filepath.Join(dir, "mydir")}, true)

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
	require.NoError(t, os.Symlink("nowhere", filepath.Join(dir, "demo", "broken")))

	dest := filepath.Join(dir, "out.zip")
	requireZip(t, dest, []string{filepath.Join(dir, "demo")}, true)

	r, err := zip.OpenReader(dest)
	require.NoError(t, err)
	defer func() { _ = r.Close() }()

	entries := make(map[string]*zip.File, len(r.File))
	for _, f := range r.File {
		entries[f.Name] = f
	}

	// One real file plus the four links: following any link would add
	// duplicates, recurse into loop, or fail outright on broken. Assert on
	// r.File as well, because the map collapses a name written twice into
	// one key.
	require.Len(t, r.File, 5)
	require.Len(t, entries, 5, "archive holds duplicate entry names")
	require.Contains(t, entries, "demo/real/file.txt")
	for name, target := range map[string]string{
		"demo/link":     "real",
		"demo/filelink": "real/file.txt",
		"demo/loop":     ".",
		"demo/broken":   "nowhere",
	} {
		entry, ok := entries[name]
		require.True(t, ok, "link entry %s missing from archive", name)
		assert.NotZero(t, entry.Mode()&os.ModeSymlink, name)
		assert.Equal(t, target, readZipEntry(t, entry), name)
	}
}

func TestCreateZip_FileModeIsPreserved(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix-specific behavior")
	}

	dir := t.TempDir()
	scripts := filepath.Join(dir, "scripts")
	require.NoError(t, os.MkdirAll(scripts, 0755))
	script := filepath.Join(scripts, "run.sh")
	require.NoError(t, os.WriteFile(script, []byte("#!/bin/sh\n"), 0644))
	require.NoError(t, os.Chmod(script, os.ModeSetuid|0755))
	plain := filepath.Join(dir, "plain.txt")
	require.NoError(t, os.WriteFile(plain, []byte("x"), 0644))
	require.NoError(t, os.Chmod(plain, 0644))

	dest := filepath.Join(dir, "out.zip")
	requireZip(t, dest, []string{scripts, plain}, true)

	r, err := zip.OpenReader(dest)
	require.NoError(t, err)
	defer func() { _ = r.Close() }()

	modes := make(map[string]os.FileMode, len(r.File))
	for _, f := range r.File {
		modes[f.Name] = f.Mode()
	}
	assert.Equal(t, os.FileMode(0755), modes["scripts/run.sh"].Perm())
	assert.Equal(t, os.FileMode(0644), modes["plain.txt"].Perm())
	// A download has no use for setuid, and Unzip hands the entry mode to
	// os.OpenFile, so the extracted file would carry it.
	assert.Zero(t, modes["scripts/run.sh"]&os.ModeSetuid)

	outDir := filepath.Join(dir, "out")
	require.NoError(t, os.MkdirAll(outDir, 0755))
	require.NoError(t, Unzip(dest, outDir))

	// Only the owner-execute bit: umask can clear the group and other bits.
	fi, err := os.Stat(filepath.Join(outDir, "scripts", "run.sh"))
	require.NoError(t, err)
	assert.NotZero(t, fi.Mode().Perm()&0100, "extracted script lost its execute bit")
}

func TestCreateZip_ModTimeIsPreserved(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "old.txt")
	require.NoError(t, os.WriteFile(src, []byte("x"), 0644))
	mtime := time.Date(2021, 3, 4, 5, 6, 8, 0, time.UTC)
	require.NoError(t, os.Chtimes(src, mtime, mtime))

	dest := filepath.Join(dir, "out.zip")
	requireZip(t, dest, []string{src}, false)

	r, err := zip.OpenReader(dest)
	require.NoError(t, err)
	defer func() { _ = r.Close() }()

	require.Len(t, r.File, 1)
	// Zip's DOS timestamp has two-second granularity.
	assert.WithinDuration(t, mtime, r.File[0].Modified, 2*time.Second)
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
	requireZip(t, dest, []string{filepath.Join(dir, "link")}, true)

	r, err := zip.OpenReader(dest)
	require.NoError(t, err)
	defer func() { _ = r.Close() }()

	require.Len(t, r.File, 1)
	assert.Equal(t, "link/file.txt", r.File[0].Name)
}

func TestCreateZip_SymlinkedFileIsFollowed(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix-specific behavior")
	}

	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "real.txt"), []byte("hi"), 0644))
	link := filepath.Join(dir, "link.txt")
	require.NoError(t, os.Symlink("real.txt", link))

	dest := filepath.Join(dir, "out.zip")
	requireZip(t, dest, []string{link}, false)

	r, err := zip.OpenReader(dest)
	require.NoError(t, err)
	defer func() { _ = r.Close() }()

	require.Len(t, r.File, 1)
	assert.Equal(t, "link.txt", r.File[0].Name)
	assert.Zero(t, r.File[0].Mode()&os.ModeSymlink)
	assert.Equal(t, "hi", readZipEntry(t, r.File[0]))
}

func TestCreateZip_BulkMultiplePaths(t *testing.T) {
	dir := t.TempDir()
	f1 := filepath.Join(dir, "one.txt")
	f2 := filepath.Join(dir, "two.txt")
	require.NoError(t, os.WriteFile(f1, []byte("1"), 0644))
	require.NoError(t, os.WriteFile(f2, []byte("2"), 0644))

	dest := filepath.Join(dir, "out.zip")
	requireZip(t, dest, []string{f1, f2}, true)

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
	requireZip(t, zipPath, []string{srcDir}, true)

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
