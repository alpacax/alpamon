package utils

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// writeZip builds a zip at path with one entry per name/content pair. A nil
// map produces an empty zip.
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
	writeEntryZip(t, zipPath, []zipEntry{
		{name: "root.txt", body: "root"},
		{name: "sub/nested.txt", body: "nested"},
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
	writeEntryZip(t, zipPath, []zipEntry{{name: "../../etc/passwd", body: "malicious"}})

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

// zipEntry is one entry for writeEntryZip: with isLink set, body is the link
// target. A slice keeps the archive order, which the map writeZip takes cannot.
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

func TestUnzip_MissingDestinationDirectoryIsCreated(t *testing.T) {
	dir := t.TempDir()
	zipPath := filepath.Join(dir, "plain.zip")
	writeEntryZip(t, zipPath, []zipEntry{{name: "file.txt", body: "hi"}})

	// The destination used to appear on its own with the first entry, and the
	// upload path is not the only caller of an exported function.
	out := filepath.Join(dir, "missing")
	require.NoError(t, Unzip(zipPath, out))

	content, err := os.ReadFile(filepath.Join(out, "file.txt"))
	require.NoError(t, err)
	assert.Equal(t, "hi", string(content))
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
	// A link entry used to come back as a plain file holding the target path.
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

	// Extraction runs as root on a normal install, so this entry would land as
	// a root-owned setuid file.
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
	// An over-long body used to arrive truncated: a link to a path the archive
	// never named.
	writeEntryZip(t, zipPath, []zipEntry{
		{name: "link", body: strings.Repeat("a", maxSymlinkTarget+1), isLink: true},
	})

	out := filepath.Join(dir, "out")
	require.NoError(t, os.MkdirAll(out, 0755))

	assert.ErrorContains(t, Unzip(zipPath, out), "illegal link target in zip")

	_, err := os.Lstat(filepath.Join(out, "link"))
	assert.ErrorIs(t, err, os.ErrNotExist)
}

func TestUnzip_RejectionMessageEscapesControlBytes(t *testing.T) {
	dir := t.TempDir()
	zipPath := filepath.Join(dir, "esc.zip")
	// The rejection reaches the console as the command result, so an escape
	// sequence in an entry name would arrive at a terminal as live input.
	writeEntryZip(t, zipPath, []zipEntry{{name: "\x1b[2Jgone", body: "/etc", isLink: true}})

	out := filepath.Join(dir, "out")
	require.NoError(t, os.MkdirAll(out, 0755))

	err := Unzip(zipPath, out)
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "\x1b")
}

func TestUnzip_ControlBytesInEntryNameAreRejected(t *testing.T) {
	dir := t.TempDir()
	zipPath := filepath.Join(dir, "esc.zip")
	// An OS error embeds the raw path where %q cannot reach it, so a name
	// carrying control bytes must not get far enough to raise one.
	writeEntryZip(t, zipPath, []zipEntry{{name: "d\x1b[2J/x.txt", body: "x"}})

	out := filepath.Join(dir, "out")
	require.NoError(t, os.MkdirAll(out, 0755))

	err := Unzip(zipPath, out)
	assert.ErrorContains(t, err, "illegal file path in zip")
	assert.NotContains(t, err.Error(), "\x1b")
}

func TestUnzip_ControlBytesInLinkTargetAreRejected(t *testing.T) {
	dir := t.TempDir()
	zipPath := filepath.Join(dir, "esc.zip")
	// The same route the entry-name check closes: a failure past the checks
	// wraps the OS error, which embeds the raw target where %q cannot reach.
	writeEntryZip(t, zipPath, []zipEntry{{name: "lnk", body: "\x1b[2Jx", isLink: true}})

	out := filepath.Join(dir, "out")
	require.NoError(t, os.MkdirAll(out, 0755))

	err := Unzip(zipPath, out)
	assert.ErrorContains(t, err, "illegal link target in zip")
	assert.NotContains(t, err.Error(), "\x1b")
}

func TestUnzip_EntryWrittenUnderAFileIsRejected(t *testing.T) {
	dir := t.TempDir()
	zipPath := filepath.Join(dir, "under.zip")
	// Without its own check this surfaces as the raw ENOTDIR from OpenFile.
	writeEntryZip(t, zipPath, []zipEntry{
		{name: "d", body: "keep"},
		{name: "d/child.txt", body: "y"},
	})

	out := filepath.Join(dir, "out")
	require.NoError(t, os.MkdirAll(out, 0755))

	assert.ErrorContains(t, Unzip(zipPath, out), "illegal entry in zip")

	content, err := os.ReadFile(filepath.Join(out, "d"))
	require.NoError(t, err)
	assert.Equal(t, "keep", string(content))
}

func TestUnzip_LinkThroughAnEarlierLinkEntryIsRejected(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix-specific behavior")
	}

	// "a" is a real directory while the first pass checks a/c's parent, and a
	// link to "." by the time the second pass writes a/c: written through it,
	// the entry would land at c and its target would resolve from the
	// destination's parent, straight past every lexical check.
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "secret"), []byte("TOP SECRET"), 0600))
	zipPath := filepath.Join(dir, "esc.zip")
	writeEntryZip(t, zipPath, []zipEntry{
		{name: "a", body: ".", isLink: true},
		{name: "a/c", body: "../secret", isLink: true},
	})

	out := filepath.Join(dir, "out")
	require.NoError(t, os.Mkdir(out, 0755))

	assert.ErrorContains(t, Unzip(zipPath, out), "written through a symlink")

	_, err := os.Lstat(filepath.Join(out, "c"))
	assert.ErrorIs(t, err, os.ErrNotExist)
}

func TestUnzip_EscapingLinkTargetIsRejected(t *testing.T) {
	// Both names pass the entry-name check; only the link target puts the
	// second write outside.
	escaping := []zipEntry{
		{name: "a", body: "../../etc", isLink: true},
		{name: "a/passwd", body: "malicious"},
	}
	// Nothing constrains entry order, so a link arriving after the path that
	// goes through it must be rejected just the same.
	for _, tt := range []struct {
		name    string
		entries []zipEntry
	}{
		{"link first", escaping},
		{"link last", []zipEntry{escaping[1], escaping[0]}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			zipPath := filepath.Join(dir, "evil.zip")
			writeEntryZip(t, zipPath, tt.entries)

			out := filepath.Join(dir, "out")
			require.NoError(t, os.MkdirAll(out, 0755))

			assert.ErrorContains(t, Unzip(zipPath, out), "illegal link target in zip")
		})
	}
}

func TestUnzip_LinkTargetThroughAnotherLinkIsRejected(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix-specific behavior")
	}

	// filepath.Join folds "subdir/parent/.." into "subdir", so a target checked
	// by text alone lands inside. The kernel follows subdir/parent first and
	// ends up one level above destDir.
	chain := []zipEntry{
		{name: "subdir/keep", body: "x"},
		{name: "subdir/parent", body: "..", isLink: true},
		{name: "escape", body: "subdir/parent/..", isLink: true},
	}
	// Nothing constrains entry order, so the link that makes the chain escape
	// may also arrive after the link that rides it.
	for _, tt := range []struct {
		name    string
		entries []zipEntry
	}{
		{"rider last", chain},
		{"rider first", []zipEntry{chain[2], chain[0], chain[1]}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			zipPath := filepath.Join(dir, "chain.zip")
			writeEntryZip(t, zipPath, tt.entries)

			out := filepath.Join(dir, "out")
			require.NoError(t, os.MkdirAll(out, 0755))

			assert.ErrorContains(t, Unzip(zipPath, out), "illegal link target in zip")

			_, err := os.Lstat(filepath.Join(out, "escape"))
			assert.ErrorIs(t, err, os.ErrNotExist)
		})
	}
}

func TestUnzip_RejectionLeavesNoEscapingLink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix-specific behavior")
	}

	// Every link passes the check at creation time because subdir/parent is
	// not on disk yet, so the sweep after the last entry is the only barrier
	// these links have. It must keep going past the first one it removes,
	// and it must run even when a later entry ended the extraction early.
	for _, tt := range []struct {
		name    string
		entries []zipEntry
		links   []string
	}{
		{
			name: "second offender after the first",
			entries: []zipEntry{
				{name: "subdir/keep", body: "x"},
				{name: "escape1", body: "subdir/parent/..", isLink: true},
				{name: "escape2", body: "subdir/parent/..", isLink: true},
				{name: "subdir/parent", body: "..", isLink: true},
			},
			links: []string{"escape1", "escape2"},
		},
		{
			name: "entry rejected at creation",
			entries: []zipEntry{
				{name: "subdir/keep", body: "x"},
				{name: "escape", body: "subdir/parent/..", isLink: true},
				{name: "subdir/parent", body: "..", isLink: true},
				{name: "bad", body: "/etc", isLink: true},
			},
			links: []string{"escape"},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			zipPath := filepath.Join(dir, "chain.zip")
			writeEntryZip(t, zipPath, tt.entries)

			out := filepath.Join(dir, "out")
			require.NoError(t, os.MkdirAll(out, 0755))

			assert.ErrorContains(t, Unzip(zipPath, out), "illegal link target in zip")

			for _, name := range tt.links {
				_, err := os.Lstat(filepath.Join(out, name))
				assert.ErrorIs(t, err, os.ErrNotExist, name)
			}
		})
	}
}

func TestUnzip_DeepLinkTargetWithoutLinksIsAccepted(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix-specific behavior")
	}

	dir := t.TempDir()
	zipPath := filepath.Join(dir, "deep.zip")
	// The resolution bound counts links followed, not path components, so a
	// tree deeper than the bound still round-trips when nothing in it is a
	// link.
	deep := strings.Repeat("d/", maxLinkResolution+8) + "file.txt"
	writeEntryZip(t, zipPath, []zipEntry{
		{name: deep, body: "hi"},
		{name: "link", body: deep, isLink: true},
		{name: "dots", body: strings.Repeat("./", maxLinkResolution+8) + "link", isLink: true},
	})

	out := filepath.Join(dir, "out")
	require.NoError(t, os.MkdirAll(out, 0755))
	require.NoError(t, Unzip(zipPath, out))

	content, err := os.ReadFile(filepath.Join(out, "dots"))
	require.NoError(t, err)
	assert.Equal(t, "hi", string(content))
}

func TestUnzip_LinkWalkPastTheComponentBoundIsRejected(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix-specific behavior")
	}

	// The hops stay under maxLinkResolution and each target under what the
	// host allows, yet the walk visits far more components than the bound
	// allows, since every hop splices its whole target in. Left unbounded, a
	// small archive keeps a worker busy for tens of seconds.
	// Under the 1024-byte target macOS allows.
	padding := strings.Repeat("x/../", 196)
	perHop := strings.Count(padding, "/")
	hops := maxLinkWalk/perHop + 2
	require.Less(t, hops, maxLinkResolution)

	entries := []zipEntry{{name: "file.txt", body: "hi"}}
	for i := range hops {
		next := fmt.Sprintf("hop%d", i+1)
		if i == hops-1 {
			next = "file.txt"
		}
		entries = append(entries, zipEntry{name: fmt.Sprintf("hop%d", i), body: padding + next, isLink: true})
	}

	dir := t.TempDir()
	zipPath := filepath.Join(dir, "long.zip")
	writeEntryZip(t, zipPath, entries)

	out := filepath.Join(dir, "out")
	require.NoError(t, os.MkdirAll(out, 0755))

	assert.ErrorContains(t, Unzip(zipPath, out), "illegal link target in zip")
}

func TestUnzip_LinkCycleIsKeptButUnresolvable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix-specific behavior")
	}

	dir := t.TempDir()
	zipPath := filepath.Join(dir, "cycle.zip")
	// A link that resolves through a cycle never lands anywhere: the kernel
	// answers anyone who tries with ELOOP, so it can carry nobody outside and
	// failing the archive over it would refuse a tree the host itself allows.
	writeEntryZip(t, zipPath, []zipEntry{
		{name: "a", body: "b", isLink: true},
		{name: "b", body: "a", isLink: true},
		{name: "rider", body: "a/file.txt", isLink: true},
	})

	out := filepath.Join(dir, "out")
	require.NoError(t, os.MkdirAll(out, 0755))

	require.NoError(t, Unzip(zipPath, out))

	got, err := os.Readlink(filepath.Join(out, "a"))
	require.NoError(t, err)
	assert.Equal(t, "b", got)
	_, err = os.Stat(filepath.Join(out, "rider"))
	assert.ErrorContains(t, err, "too many levels of symbolic links")
}

func TestCreateZipAndUnzip_SelfReferentialLinkSurvives(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix-specific behavior")
	}

	// The host allows x -> x on disk, so CreateZip archives it and the round
	// trip must not end in a rejection.
	dir := t.TempDir()
	srcDir := filepath.Join(dir, "src")
	require.NoError(t, os.Mkdir(srcDir, 0755))
	require.NoError(t, os.Symlink("x", filepath.Join(srcDir, "x")))

	zipPath := filepath.Join(dir, "self.zip")
	requireZip(t, zipPath, []string{srcDir}, true)

	out := filepath.Join(dir, "out")
	require.NoError(t, os.Mkdir(out, 0755))
	require.NoError(t, Unzip(zipPath, out))

	got, err := os.Readlink(filepath.Join(out, "src", "x"))
	require.NoError(t, err)
	assert.Equal(t, "x", got)
}

func TestUnzip_DirectoryModeFromANonUnixArchiveIsIgnored(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix-specific behavior")
	}

	dir := t.TempDir()
	zipPath := filepath.Join(dir, "fat.zip")
	f, err := os.Create(zipPath)
	require.NoError(t, err)
	w := zip.NewWriter(f)
	// No SetMode: a FAT-creator header, the kind Compress-Archive writes.
	// archive/zip derives 0666 from its attributes, a directory nobody chose
	// to make unenterable.
	_, err = w.CreateHeader(&zip.FileHeader{Name: "sub/", Method: zip.Store})
	require.NoError(t, err)
	zw, err := w.Create("sub/f.txt")
	require.NoError(t, err)
	_, err = zw.Write([]byte("x"))
	require.NoError(t, err)
	require.NoError(t, w.Close())
	require.NoError(t, f.Close())

	out := filepath.Join(dir, "out")
	require.NoError(t, os.Mkdir(out, 0755))
	require.NoError(t, Unzip(zipPath, out))

	ref := filepath.Join(dir, "ref")
	require.NoError(t, os.Mkdir(ref, 0755))
	refInfo, err := os.Stat(ref)
	require.NoError(t, err)

	fi, err := os.Stat(filepath.Join(out, "sub"))
	require.NoError(t, err)
	assert.Equal(t, refInfo.Mode().Perm(), fi.Mode().Perm())
}

func TestUnzip_LinkTargetMayGoThroughALinkInsideRoot(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix-specific behavior")
	}

	dir := t.TempDir()
	zipPath := filepath.Join(dir, "chain.zip")
	// Resolving the target must not turn every earlier link into a refusal:
	// this chain stays inside destDir the whole way.
	writeEntryZip(t, zipPath, []zipEntry{
		{name: "subdir/file.txt", body: "hi"},
		{name: "alias", body: "subdir", isLink: true},
		{name: "indirect", body: "alias/file.txt", isLink: true},
	})

	out := filepath.Join(dir, "out")
	require.NoError(t, os.MkdirAll(out, 0755))
	require.NoError(t, Unzip(zipPath, out))

	content, err := os.ReadFile(filepath.Join(out, "indirect"))
	require.NoError(t, err)
	assert.Equal(t, "hi", string(content))
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
	// user's own directory, where one can already be sitting.
	require.NoError(t, os.Symlink(outside, filepath.Join(out, "a")))

	zipPath := filepath.Join(dir, "evil.zip")
	writeEntryZip(t, zipPath, []zipEntry{{name: "a/passwd", body: "malicious"}})

	// The entry is a plain file, so the rejection names the entry rather than
	// a link target it does not have.
	assert.ErrorContains(t, Unzip(zipPath, out), `illegal entry in zip: "a/passwd" is written through a symlink`)

	_, err := os.Stat(filepath.Join(outside, "passwd"))
	assert.ErrorIs(t, err, os.ErrNotExist, "the entry was written through the link")
}

func TestUnzip_ConcurrentExtractionsIntoOneDestination(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix-specific behavior")
	}

	dir := t.TempDir()
	zipPath := filepath.Join(dir, "links.zip")
	writeEntryZip(t, zipPath, []zipEntry{
		{name: "file.txt", body: "hi"},
		{name: "sub/file.txt", body: "hi"},
		{name: "link", body: "file.txt", isLink: true},
		{name: "sub/link", body: "file.txt", isLink: true},
	})

	out := filepath.Join(dir, "out")
	require.NoError(t, os.MkdirAll(out, 0755))

	// Commands run on a worker pool, so one directory can take two extractions
	// at once. A regular entry rides that out because O_TRUNC overwrites in a
	// single call, while a link is removed and created in two.
	const workers = 8
	errs := make(chan error, workers)
	var start sync.WaitGroup
	start.Add(1)
	for range workers {
		go func() {
			start.Wait()
			errs <- Unzip(zipPath, out)
		}()
	}
	start.Done()
	for range workers {
		assert.NoError(t, <-errs)
	}

	target, err := os.Readlink(filepath.Join(out, "link"))
	require.NoError(t, err)
	assert.Equal(t, "file.txt", target)
}

func TestCreateZipAndUnzip_EmptyDirectorySurvives(t *testing.T) {
	dir := t.TempDir()
	srcDir := filepath.Join(dir, "src")
	require.NoError(t, os.MkdirAll(filepath.Join(srcDir, "empty"), 0755))
	require.NoError(t, os.WriteFile(filepath.Join(srcDir, "a.txt"), []byte("aaa"), 0644))

	zipPath := filepath.Join(dir, "archive.zip")
	requireZip(t, zipPath, []string{srcDir}, true)

	out := filepath.Join(dir, "out")
	require.NoError(t, os.MkdirAll(out, 0755))
	require.NoError(t, Unzip(zipPath, out))

	// A directory holding nothing has no file entry to carry it, so it needs an
	// entry of its own or the download drops it.
	assert.DirExists(t, filepath.Join(out, "src", "empty"))
}

func TestCreateZipAndUnzip_EmptyDirectoryModeIsPreserved(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix-specific behavior")
	}

	dir := t.TempDir()
	srcDir := filepath.Join(dir, "src")
	private := filepath.Join(srcDir, "private")
	require.NoError(t, os.MkdirAll(private, 0700))
	require.NoError(t, os.WriteFile(filepath.Join(srcDir, "a.txt"), []byte("aaa"), 0644))

	zipPath := filepath.Join(dir, "archive.zip")
	requireZip(t, zipPath, []string{srcDir}, true)

	out := filepath.Join(dir, "out")
	require.NoError(t, os.MkdirAll(out, 0755))
	require.NoError(t, Unzip(zipPath, out))

	// Only a directory holding nothing gets an entry of its own, so it is the
	// one whose mode makes the trip; one holding files comes back with the
	// default. Extraction runs as root on a normal install, so a directory
	// that came back wider than it left would be readable by everyone on the
	// host.
	fi, err := os.Stat(filepath.Join(out, "src", "private"))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0700), fi.Mode().Perm())
}

func TestUnzip_EntryNamingTheDestinationLeavesItsModeAlone(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix-specific behavior")
	}

	// filepath.Join folds each of these names onto the destination itself. That
	// directory is the caller's, so the mode the archive carries for it must
	// not land: extraction runs as root, and 0777 here would open a user's home
	// directory to everyone on the host.
	for _, name := range []string{".", "./", "", "sub/../"} {
		t.Run(fmt.Sprintf("%q", name), func(t *testing.T) {
			dir := t.TempDir()
			zipPath := filepath.Join(dir, "self.zip")
			writeEntryZip(t, zipPath, []zipEntry{
				{name: name, mode: 0777 | os.ModeDir},
				{name: "a.txt", body: "aaa"},
			})

			out := filepath.Join(dir, "out")
			require.NoError(t, os.Mkdir(out, 0750))
			before, err := os.Stat(out)
			require.NoError(t, err)

			require.NoError(t, Unzip(zipPath, out))

			after, err := os.Stat(out)
			require.NoError(t, err)
			assert.Equal(t, before.Mode().Perm(), after.Mode().Perm())
			assert.FileExists(t, filepath.Join(out, "a.txt"))
		})
	}
}

func TestUnzip_EntryReplacingTheDestinationIsRejected(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix-specific behavior")
	}

	// A link entry at the destination's own name passes the target check with
	// "." and would then swap the caller's directory for a link, since
	// createSymlink removes whatever holds the path first.
	for _, tt := range []struct {
		name  string
		entry zipEntry
	}{
		{name: "link", entry: zipEntry{name: ".", body: ".", isLink: true}},
		{name: "file", entry: zipEntry{name: ".", body: "x"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			zipPath := filepath.Join(dir, "self.zip")
			writeEntryZip(t, zipPath, []zipEntry{tt.entry})

			out := filepath.Join(dir, "out")
			require.NoError(t, os.Mkdir(out, 0755))

			assert.ErrorContains(t, Unzip(zipPath, out), "illegal file path in zip")

			fi, err := os.Lstat(out)
			require.NoError(t, err)
			assert.True(t, fi.IsDir())
		})
	}
}

func TestCreateFile_DoesNotWriteThroughALink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix-specific behavior")
	}

	// extractFile clears a link before it opens the path, but another
	// extraction into the same destination can put one back in between, and
	// the open must not carry the entry's content through it.
	dir := t.TempDir()
	victim := filepath.Join(dir, "victim.txt")
	require.NoError(t, os.WriteFile(victim, []byte("keep"), 0644))
	link := filepath.Join(dir, "link")
	require.NoError(t, os.Symlink("victim.txt", link))

	f, err := createFile(link, 0644)
	if err == nil {
		_ = f.Close()
	}
	assert.Error(t, err)

	content, err := os.ReadFile(victim)
	require.NoError(t, err)
	assert.Equal(t, "keep", string(content))
}

func TestRecheckLinks_OffenderLeftOnDiskOutranksTheOnesRemoved(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix-specific behavior")
	}
	if os.Getuid() == 0 {
		t.Skip("root removes from a read-only directory regardless")
	}

	// No archive can leave a link's parent read-only before the sweep, since
	// directory modes land after it, so the sweep is driven directly.
	root := t.TempDir()
	require.NoError(t, os.Mkdir(filepath.Join(root, "ro"), 0755))
	require.NoError(t, os.Symlink("../..", filepath.Join(root, "ro", "stuck")))
	require.NoError(t, os.Symlink("..", filepath.Join(root, "gone")))
	require.NoError(t, os.Chmod(filepath.Join(root, "ro"), 0500))
	t.Cleanup(func() { _ = os.Chmod(filepath.Join(root, "ro"), 0700) })

	rejected, left := recheckLinks(root, []deferredEntry{
		{file: &zip.File{FileHeader: zip.FileHeader{Name: "gone"}}, path: filepath.Join(root, "gone")},
		{file: &zip.File{FileHeader: zip.FileHeader{Name: "ro/stuck"}}, path: filepath.Join(root, "ro", "stuck")},
	})
	assert.ErrorContains(t, rejected, `illegal link target in zip: "gone"`)
	assert.ErrorContains(t, left, `failed to remove link "ro/stuck"`)

	_, err := os.Lstat(filepath.Join(root, "gone"))
	assert.ErrorIs(t, err, os.ErrNotExist)
	_, err = os.Lstat(filepath.Join(root, "ro", "stuck"))
	assert.NoError(t, err)
}

func TestUnzip_ReadOnlyDirectoryEntryDoesNotBlockItsChildren(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix-specific behavior")
	}
	if os.Getuid() == 0 {
		t.Skip("root writes into a read-only directory regardless")
	}

	dir := t.TempDir()
	zipPath := filepath.Join(dir, "ro.zip")
	// zip -r lists a directory before what it holds, whatever the directory's
	// mode, so the mode has to land after the children or none of them can be
	// written. The parent's mode has to land after the child's too, since a
	// parent without search permission blocks the chmod below it.
	writeEntryZip(t, zipPath, []zipEntry{
		{name: "ro/", mode: 0400 | os.ModeDir},
		{name: "ro/sub/", mode: 0700 | os.ModeDir},
		{name: "ro/sub/file.txt", body: "hi"},
		{name: "ro/sub/link", body: "file.txt", isLink: true},
	})

	out := filepath.Join(dir, "out")
	require.NoError(t, os.MkdirAll(out, 0755))
	t.Cleanup(func() { _ = os.Chmod(filepath.Join(out, "ro"), 0700) })
	require.NoError(t, Unzip(zipPath, out))

	fi, err := os.Stat(filepath.Join(out, "ro"))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0400), fi.Mode().Perm())

	require.NoError(t, os.Chmod(filepath.Join(out, "ro"), 0700))
	content, err := os.ReadFile(filepath.Join(out, "ro", "sub", "link"))
	require.NoError(t, err)
	assert.Equal(t, "hi", string(content))

	fi, err = os.Stat(filepath.Join(out, "ro", "sub"))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0700), fi.Mode().Perm())
}

func TestUnzip_LinkReplacingADirectoryEntryIsRejected(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix-specific behavior")
	}

	// The link lands after the directory it is named for, so by the time the
	// directory's mode is applied the path is a link. os.Chmod follows links,
	// and the mode would land on whatever the link points at. An entry that
	// carries no mode gets nothing applied, and is refused all the same.
	for _, tt := range []struct {
		name string
		mode os.FileMode
	}{
		{"with mode", 0777 | os.ModeDir},
		{"without mode", os.ModeDir},
	} {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			zipPath := filepath.Join(dir, "swap.zip")
			writeEntryZip(t, zipPath, []zipEntry{
				{name: "victim.txt", body: "secret", mode: 0600},
				{name: "d/", mode: tt.mode},
				{name: "d", body: "victim.txt", isLink: true},
			})

			out := filepath.Join(dir, "out")
			require.NoError(t, os.MkdirAll(out, 0755))

			assert.ErrorContains(t, Unzip(zipPath, out), "illegal entry in zip")

			fi, err := os.Stat(filepath.Join(out, "victim.txt"))
			require.NoError(t, err)
			assert.Equal(t, os.FileMode(0600), fi.Mode().Perm())
		})
	}
}

func TestUnzip_DirectoryEntryWithoutModeKeepsTheDefault(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix-specific behavior")
	}

	dir := t.TempDir()
	zipPath := filepath.Join(dir, "nomode.zip")
	// A Unix-flagged archive with empty external attributes reads back as
	// mode 0, which is an absent mode rather than a directory nobody may
	// enter.
	writeEntryZip(t, zipPath, []zipEntry{
		{name: "d/", mode: os.ModeDir},
		{name: "d/file.txt", body: "hi"},
	})

	out := filepath.Join(dir, "out")
	require.NoError(t, os.MkdirAll(out, 0755))
	require.NoError(t, Unzip(zipPath, out))

	// The default is whatever os.Mkdir leaves under this process's umask, so
	// a directory made the same way is the reference, not a literal 0755.
	ref := filepath.Join(dir, "ref")
	require.NoError(t, os.Mkdir(ref, 0755))
	want, err := os.Stat(ref)
	require.NoError(t, err)
	fi, err := os.Stat(filepath.Join(out, "d"))
	require.NoError(t, err)
	assert.Equal(t, want.Mode().Perm(), fi.Mode().Perm())

	content, err := os.ReadFile(filepath.Join(out, "d", "file.txt"))
	require.NoError(t, err)
	assert.Equal(t, "hi", string(content))
}

func TestUnzipReader_ExtractsAnInMemoryArchive(t *testing.T) {
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	zw, err := w.Create("hello.txt")
	require.NoError(t, err)
	_, err = zw.Write([]byte("hi"))
	require.NoError(t, err)
	require.NoError(t, w.Close())

	// Nothing here was ever a file, so there is no ReadCloser to hand over.
	r, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	require.NoError(t, err)

	out := filepath.Join(t.TempDir(), "out")
	require.NoError(t, UnzipReader(r, out))

	content, err := os.ReadFile(filepath.Join(out, "hello.txt"))
	require.NoError(t, err)
	assert.Equal(t, "hi", string(content))
}

func TestUnzip_ErrorNamesTheEntry(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix-specific behavior")
	}

	dir := t.TempDir()
	zipPath := filepath.Join(dir, "collide.zip")
	// The error reaches the console as the command result, so a bare OS error
	// with an internal absolute path and no entry name is not actionable.
	writeEntryZip(t, zipPath, []zipEntry{
		{name: "d/file.txt", body: "hi"},
		{name: "d", body: "file.txt", isLink: true},
	})

	out := filepath.Join(dir, "out")
	require.NoError(t, os.MkdirAll(out, 0755))

	assert.ErrorContains(t, Unzip(zipPath, out), `link "d"`)
}

func TestIsEmptyDir(t *testing.T) {
	dir := t.TempDir()
	empty, err := isEmptyDir(dir)
	require.NoError(t, err)
	assert.True(t, empty)

	require.NoError(t, os.WriteFile(filepath.Join(dir, "a"), nil, 0644))
	empty, err = isEmptyDir(dir)
	require.NoError(t, err)
	assert.False(t, empty)

	_, err = isEmptyDir(filepath.Join(dir, "missing"))
	assert.ErrorIs(t, err, os.ErrNotExist)
}
