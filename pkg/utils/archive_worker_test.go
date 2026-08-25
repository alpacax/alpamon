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
	"unicode/utf8"

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

func TestShortenSkippedPath_KeepsThePathReadable(t *testing.T) {
	// Non-ASCII names are ordinary on the machines this runs on, and Hangul is
	// three bytes a rune, so most byte offsets land inside one. The padding
	// walks the cut across every offset within a rune.
	base := "/home/사용자/" + strings.Repeat("내려받기폴더/", 12)
	for i := 0; i < 12; i++ {
		path := base + strings.Repeat("a", i) + "비밀문서.zip"
		require.Greater(t, len(path), archiveSkippedPathMax, "input must be long enough to shorten")

		got := shortenSkippedPath(path)

		assert.True(t, utf8.ValidString(got),
			"padding %d produced invalid UTF-8, which json.Marshal replaces with U+FFFD: %q", i, got)
		assert.LessOrEqual(t, len(got), archiveSkippedPathMax+3, "padding %d overshot the bound", i)
		assert.True(t, strings.HasSuffix(got, "비밀문서.zip"), "padding %d lost the leaf", i)
	}
}

func TestShortenSkippedPath_LeavesAShortPathAlone(t *testing.T) {
	path := "/home/u/secret.txt"
	assert.Equal(t, path, shortenSkippedPath(path))
}

func TestEncodeArchiveStatus_StaysParseableWhateverItCarries(t *testing.T) {
	// A wrapped *PathError reaches PATH_MAX, and the sample budget does not
	// count the error field, so a full sample plus a long error overruns the
	// buffer that carries the status. A status the parent cannot parse costs it
	// the error message too, which is the one thing it still needed.
	resp := ArchiveResponse{
		SkippedTotal: 500,
		Error:        "failed to write zip entry: read " + strings.Repeat("긴경로/", 900) + ": i/o error",
	}
	for i := 0; i < archiveSkippedReported; i++ {
		resp.Skipped = append(resp.Skipped, ArchiveSkipped{
			Path:   "..." + strings.Repeat("p", archiveSkippedPathMax),
			Reason: "permission denied",
		})
	}

	var buf bytes.Buffer
	encodeArchiveStatus(&buf, resp)

	assert.LessOrEqual(t, buf.Len(), archiveStatusMax, "encoded status overran its bound")
	var got ArchiveResponse
	require.NoError(t, json.Unmarshal(buf.Bytes(), &got), "status must always parse")
	// The count survives even when the sample is dropped, so the summary can
	// still say how much was left out.
	assert.Equal(t, 500, got.SkippedTotal)
	assert.NotEmpty(t, got.Error, "the reason for the failure must survive")
	assert.True(t, utf8.ValidString(got.Error), "a truncated error must stay readable")
}
