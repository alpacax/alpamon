package utils

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRunArchiveWorker_WritesZipAndReportsSkipped(t *testing.T) {
	dir := t.TempDir()
	present := filepath.Join(dir, "present.txt")
	require.NoError(t, os.WriteFile(present, []byte("hi"), 0644))
	missing := filepath.Join(dir, "missing.txt")

	req, err := json.Marshal(ArchiveRequest{Paths: []string{present, missing}})
	require.NoError(t, err)

	dest := filepath.Join(dir, "out.zip")
	f, err := os.Create(dest)
	require.NoError(t, err)
	var status bytes.Buffer

	code := RunArchiveWorker(bytes.NewReader(req), f, &status)
	require.NoError(t, f.Close())
	require.Zero(t, code)

	var resp ArchiveResponse
	require.NoError(t, json.Unmarshal(status.Bytes(), &resp))
	assert.Empty(t, resp.Error)
	// The parent cannot see what the demoted worker could not open, so the
	// reason has to survive the process boundary as text.
	require.Len(t, resp.Skipped, 1)
	assert.Equal(t, missing, resp.Skipped[0].Path)
	assert.Contains(t, resp.Skipped[0].Reason, "no such file")

	r, err := zip.OpenReader(dest)
	require.NoError(t, err)
	defer func() { _ = r.Close() }()
	require.Len(t, r.File, 1)
	assert.Equal(t, "present.txt", r.File[0].Name)
}

func TestRunArchiveWorker_ReportsAnUnreadableRequest(t *testing.T) {
	var status bytes.Buffer

	code := RunArchiveWorker(strings.NewReader("not json"), io.Discard, &status)

	assert.Equal(t, 1, code)
	var resp ArchiveResponse
	require.NoError(t, json.Unmarshal(status.Bytes(), &resp))
	assert.Contains(t, resp.Error, "failed to read archive request")
}

func TestRunArchiveWorker_ReportsAnArchiveThatHeldNothing(t *testing.T) {
	dir := t.TempDir()
	req, err := json.Marshal(ArchiveRequest{Paths: []string{filepath.Join(dir, "gone.txt")}})
	require.NoError(t, err)
	var status bytes.Buffer

	// Every path skipped is the empty-archive case, and the exit code is what
	// the parent keys off, so it must not read as a finished download.
	code := RunArchiveWorker(bytes.NewReader(req), io.Discard, &status)

	assert.Equal(t, 1, code)
	var resp ArchiveResponse
	require.NoError(t, json.Unmarshal(status.Bytes(), &resp))
	assert.Contains(t, resp.Error, "nothing could be archived")
	assert.Len(t, resp.Skipped, 1)
}
