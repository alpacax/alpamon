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

	src, err := os.Open(zipPath)
	require.NoError(t, err)
	defer func() { _ = src.Close() }()

	dest := filepath.Join(dir, "out")
	require.NoError(t, os.MkdirAll(dest, 0755))
	var status bytes.Buffer

	code := RunExtractWorker(src, dest, &status)

	require.Zero(t, code, status.String())
	content, err := os.ReadFile(filepath.Join(dest, "sub", "b.txt"))
	require.NoError(t, err)
	assert.Equal(t, "bbb", string(content))
}

func TestRunExtractWorker_ReportsAZipItCannotRead(t *testing.T) {
	dir := t.TempDir()
	plain := filepath.Join(dir, "plain.txt")
	require.NoError(t, os.WriteFile(plain, []byte("not a zip"), 0644))

	src, err := os.Open(plain)
	require.NoError(t, err)
	defer func() { _ = src.Close() }()
	var status bytes.Buffer

	code := RunExtractWorker(src, dir, &status)

	// The parent keys off the exit code, so a refused extraction must not
	// read as a finished one.
	assert.Equal(t, 1, code)
	assert.NotEmpty(t, status.String())
}

func TestRunExtractWorker_RejectsZipSlip(t *testing.T) {
	dir := t.TempDir()
	zipPath := filepath.Join(dir, "evil.zip")
	writeEntryZip(t, zipPath, []zipEntry{{name: "../escaped.txt", body: "x"}})

	src, err := os.Open(zipPath)
	require.NoError(t, err)
	defer func() { _ = src.Close() }()

	dest := filepath.Join(dir, "out")
	require.NoError(t, os.MkdirAll(dest, 0755))
	var status bytes.Buffer

	code := RunExtractWorker(src, dest, &status)

	assert.Equal(t, 1, code)
	assert.Contains(t, status.String(), "illegal file path in zip")
	assert.NoFileExists(t, filepath.Join(dir, "escaped.txt"))
}
