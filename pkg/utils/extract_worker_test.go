package utils

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRunExtractWorker_ExtractsIntoTheDestination(t *testing.T) {
	dir := t.TempDir()
	zipPath := filepath.Join(dir, "payload.zip")
	writeEntryZip(t, zipPath, []zipEntry{{name: "a.txt", body: "aaa"}, {name: "sub/b.txt", body: "bbb"}})

	dest := filepath.Join(dir, "out")
	require.NoError(t, os.MkdirAll(dest, 0755))
	var status bytes.Buffer

	code := RunExtractWorker(zipPath, dest, &status)

	require.Zero(t, code, status.String())
	content, err := os.ReadFile(filepath.Join(dest, "sub", "b.txt"))
	require.NoError(t, err)
	assert.Equal(t, "bbb", string(content))
}

func TestRunExtractWorker_RemovesTheSourceAfterExtracting(t *testing.T) {
	dir := t.TempDir()
	zipPath := filepath.Join(dir, "payload.zip")
	writeEntryZip(t, zipPath, []zipEntry{{name: "a.txt", body: "aaa"}})

	dest := filepath.Join(dir, "out")
	require.NoError(t, os.MkdirAll(dest, 0755))
	var status bytes.Buffer

	// The worker owns the cleanup, so the agent never unlinks a path the
	// requesting user controls.
	require.Zero(t, RunExtractWorker(zipPath, dest, &status), status.String())

	_, err := os.Stat(zipPath)
	assert.ErrorIs(t, err, os.ErrNotExist)
}

func TestRunExtractWorker_LeavesANonZipAlone(t *testing.T) {
	dir := t.TempDir()
	plain := filepath.Join(dir, "plain.txt")
	require.NoError(t, os.WriteFile(plain, []byte("not a zip"), 0644))

	dest := filepath.Join(dir, "out")
	require.NoError(t, os.MkdirAll(dest, 0755))
	var status bytes.Buffer

	// Not being an archive is not a failure: the download stands and nothing
	// is extracted, so the source must survive.
	code := RunExtractWorker(plain, dest, &status)

	assert.Zero(t, code)
	assert.FileExists(t, plain)
	entries, err := os.ReadDir(dest)
	require.NoError(t, err)
	assert.Empty(t, entries)
}

func TestRunExtractWorker_TreatsAnUnopenableSourceAsNotAnArchive(t *testing.T) {
	dir := t.TempDir()
	var status bytes.Buffer

	// A path the worker cannot open is indistinguishable from "not an
	// archive" and must not extract anything.
	code := RunExtractWorker(filepath.Join(dir, "missing.zip"), dir, &status)

	assert.Zero(t, code)
}

func TestRunExtractWorker_RejectsZipSlip(t *testing.T) {
	dir := t.TempDir()
	zipPath := filepath.Join(dir, "evil.zip")
	writeEntryZip(t, zipPath, []zipEntry{{name: "../escaped.txt", body: "x"}})

	dest := filepath.Join(dir, "out")
	require.NoError(t, os.MkdirAll(dest, 0755))
	var status bytes.Buffer

	code := RunExtractWorker(zipPath, dest, &status)

	assert.Equal(t, 1, code)
	assert.Contains(t, status.String(), "illegal file path in zip")
	assert.NoFileExists(t, filepath.Join(dir, "escaped.txt"))
	// A refused archive is not cleaned up; the operator can still inspect it.
	assert.FileExists(t, zipPath)
}
