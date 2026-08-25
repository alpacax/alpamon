package utils

import (
	"archive/zip"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
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

// zipEntry is one entry for writeEntryZip: with isLink set it carries its
// target as the body. A slice keeps the archive order, which the map writeZip
// takes cannot.
type zipEntry struct {
	name   string
	body   string
	isLink bool
	mode   os.FileMode // zero means a plain 0644 file
}

func writeEntryZip(t *testing.T, path string, entries []zipEntry) {
	t.Helper()
	f, err := os.Create(path)
	require.NoError(t, err)
	w := zip.NewWriter(f)
	for _, e := range entries {
		mode := e.mode
		switch {
		case e.isLink:
			mode = 0777 | os.ModeSymlink
		case mode == 0:
			mode = 0644
		}
		hdr := &zip.FileHeader{Name: e.name, Method: zip.Store}
		hdr.SetMode(mode)
		zw, err := w.CreateHeader(hdr)
		require.NoError(t, err)
		_, err = zw.Write([]byte(e.body))
		require.NoError(t, err)
	}
	require.NoError(t, w.Close())
	require.NoError(t, f.Close())
}

func TestUnzip_SymlinkIsRestored(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix-specific behavior")
	}

	dir := t.TempDir()
	demo := filepath.Join(dir, "demo")
	require.NoError(t, os.MkdirAll(filepath.Join(demo, "real"), 0755))
	require.NoError(t, os.WriteFile(filepath.Join(demo, "real", "file.txt"), []byte("hi"), 0644))
	require.NoError(t, os.Symlink("real", filepath.Join(demo, "link")))

	zipPath := filepath.Join(dir, "demo.zip")
	requireZip(t, zipPath, []string{demo}, true)

	out := filepath.Join(dir, "out")
	require.NoError(t, os.MkdirAll(out, 0755))
	require.NoError(t, Unzip(zipPath, out))

	link := filepath.Join(out, "demo", "link")
	fi, err := os.Lstat(link)
	require.NoError(t, err)
	// A link entry used to come back as a plain file holding the target path,
	// so assert the type rather than just that something is there.
	require.NotZero(t, fi.Mode()&os.ModeSymlink, "link came back as %v", fi.Mode())

	target, err := os.Readlink(link)
	require.NoError(t, err)
	assert.Equal(t, "real", target)

	content, err := os.ReadFile(filepath.Join(link, "file.txt"))
	require.NoError(t, err)
	assert.Equal(t, "hi", string(content))
}

func TestUnzip_SetuidBitIsNotRestored(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("windows has no setuid bit")
	}

	dir := t.TempDir()
	zipPath := filepath.Join(dir, "suid.zip")
	writeEntryZip(t, zipPath, []zipEntry{
		{name: "payload", body: "x", mode: 0755 | os.ModeSetuid | os.ModeSetgid | os.ModeSticky},
	})

	out := filepath.Join(dir, "out")
	require.NoError(t, os.MkdirAll(out, 0755))
	require.NoError(t, Unzip(zipPath, out))

	// Extraction runs in the alpamon process, which is root on a normal
	// install, so an entry carrying setuid would land as a root-owned setuid
	// file. newZipEntry already drops these bits when writing an archive.
	fi, err := os.Stat(filepath.Join(out, "payload"))
	require.NoError(t, err)
	assert.Zero(t, fi.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky))
}

func TestUnzip_AbsoluteLinkTargetIsRejected(t *testing.T) {
	dir := t.TempDir()
	zipPath := filepath.Join(dir, "abs.zip")
	writeEntryZip(t, zipPath, []zipEntry{{name: "etc", body: "/etc", isLink: true}})

	out := filepath.Join(dir, "out")
	require.NoError(t, os.MkdirAll(out, 0755))

	assert.ErrorContains(t, Unzip(zipPath, out), "illegal link target in zip")
}

func TestUnzip_OversizedLinkTargetIsRejected(t *testing.T) {
	dir := t.TempDir()
	zipPath := filepath.Join(dir, "long.zip")
	// The read is bounded, so an over-long body used to arrive truncated and
	// become a link to a path the archive never named.
	writeEntryZip(t, zipPath, []zipEntry{
		{name: "link", body: strings.Repeat("a", maxSymlinkTarget+1), isLink: true},
	})

	out := filepath.Join(dir, "out")
	require.NoError(t, os.MkdirAll(out, 0755))

	assert.ErrorContains(t, Unzip(zipPath, out), "illegal link target in zip")

	_, err := os.Lstat(filepath.Join(out, "link"))
	assert.ErrorIs(t, err, os.ErrNotExist)
}

func TestUnzip_EscapingLinkTargetIsRejected(t *testing.T) {
	// The entry-name check passes for both: "a" sits inside destDir and so
	// does "a/passwd". Only the link target puts the second write outside.
	escaping := []zipEntry{
		{name: "a", body: "../../etc", isLink: true},
		{name: "a/passwd", body: "malicious"},
	}
	// Nothing constrains the order entries appear in, so the link arriving
	// after the path that goes through it must be rejected just the same.
	for name, entries := range map[string][]zipEntry{
		"link first": escaping,
		"link last":  {escaping[1], escaping[0]},
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			zipPath := filepath.Join(dir, "evil.zip")
			writeEntryZip(t, zipPath, entries)

			out := filepath.Join(dir, "out")
			require.NoError(t, os.MkdirAll(out, 0755))

			assert.ErrorContains(t, Unzip(zipPath, out), "illegal link target in zip")
		})
	}
}

func TestUnzip_EntryWrittenThroughExistingLinkIsRejected(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix-specific behavior")
	}

	dir := t.TempDir()
	outside := filepath.Join(dir, "outside")
	require.NoError(t, os.MkdirAll(outside, 0755))
	out := filepath.Join(dir, "out")
	require.NoError(t, os.MkdirAll(out, 0755))
	// A link the archive never carried: the upload path extracts into the
	// user's own directory, so one can already be sitting in it.
	require.NoError(t, os.Symlink(outside, filepath.Join(out, "a")))

	zipPath := filepath.Join(dir, "evil.zip")
	writeZip(t, zipPath, map[string]string{"a/passwd": "malicious"})

	assert.ErrorContains(t, Unzip(zipPath, out), "illegal link target in zip")

	_, err := os.Stat(filepath.Join(outside, "passwd"))
	assert.ErrorIs(t, err, os.ErrNotExist, "the entry was written through the link")
}
