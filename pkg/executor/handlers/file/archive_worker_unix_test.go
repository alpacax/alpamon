//go:build !windows

package file

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alpacax/alpamon/v2/pkg/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestArchiveWorkerResult_CarriesTheSkippedList(t *testing.T) {
	// No skipped_total: the total must still not fall below what the response
	// could name, or the summary understates what the download left out.
	status := `{"skipped":[{"path":"/root/secret","reason":"permission denied"}]}`

	report, err := archiveWorkerResult(status, nil)

	require.NoError(t, err)
	require.Len(t, report.Entries, 1)
	assert.Equal(t, 1, report.Total)
	assert.Equal(t, "/root/secret", report.Entries[0].Path)
	// uploadSummary prints the reason, so it has to survive as an error value.
	assert.EqualError(t, report.Entries[0].Reason, "permission denied")
}

func TestArchiveWorkerResult_ReportsTheWorkerErrorWithWhatWasSkipped(t *testing.T) {
	status := `{"skipped":[{"path":"/root","reason":"permission denied"}],` +
		`"error":"nothing could be archived, skipped 1 path(s): permission denied"}`

	// A user who asks for a directory they cannot read must get the failure,
	// not an empty archive reported as a finished download.
	report, err := archiveWorkerResult(status, errors.New("exit status 1"))

	assert.ErrorContains(t, err, "nothing could be archived")
	assert.Len(t, report.Entries, 1)
}

func TestArchiveWorkerResult_FallsBackToTheRawStreamWhenTheWorkerDied(t *testing.T) {
	// A worker killed before it could encode leaves the stream unparseable,
	// and swallowing that would report a truncated archive as a success.
	report, err := archiveWorkerResult("signal: killed", errors.New("exit status 2"))

	assert.ErrorContains(t, err, "exit status 2")
	assert.ErrorContains(t, err, "signal: killed")
	assert.Empty(t, report.Entries)
}

func TestArchiveWorkerResult_RejectsAnUnparseableStatusOnASilentExit(t *testing.T) {
	// Exit 0 with a status nobody can read means the archive is unaccounted
	// for; treating it as an empty skipped list would hide that.
	_, err := archiveWorkerResult("", nil)

	assert.ErrorContains(t, err, "failed to read the archive worker status")
}

func TestArchiveWorkerResult_SurvivesATreeWithManyUnreadablePaths(t *testing.T) {
	dir := t.TempDir()
	present := filepath.Join(dir, "keep.txt")
	require.NoError(t, os.WriteFile(present, []byte("x"), 0644))

	paths := []string{present}
	for i := 0; i < 500; i++ {
		paths = append(paths, filepath.Join(dir, fmt.Sprintf("missing%03d.txt", i)))
	}
	request, err := json.Marshal(utils.ArchiveRequest{Paths: paths})
	require.NoError(t, err)

	// The status rides the same capped buffer the parent installs, sized for a
	// single error message. An unbounded skipped list truncates into
	// unparseable JSON, and the download fails even though the archive is
	// complete: exactly the all-or-nothing failure the skipping exists to avoid.
	status := &stderrCap{cap: stderrCapSize}
	require.Zero(t, utils.RunArchiveWorker(bytes.NewReader(request), io.Discard, status))

	report, err := archiveWorkerResult(status.buf.String(), nil)

	require.NoError(t, err)
	assert.Equal(t, 500, report.Total)
	assert.NotEmpty(t, report.Entries)
	assert.LessOrEqual(t, len(report.Entries), report.Total)
}

func TestMakeArchive_ArchivesADirectoryWithoutDemotion(t *testing.T) {
	dir := t.TempDir()
	tree := filepath.Join(dir, "tree")
	require.NoError(t, os.MkdirAll(tree, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(tree, "a.txt"), []byte("aaa"), 0644))

	h := &FileHandler{}
	// A nil descriptor is every non-root agent and the whole Windows path, so
	// this branch carries the archive whenever demotion is unavailable.
	name, cleanup, skipped, err := h.makeArchive(context.Background(), []string{tree}, false, true, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.Remove(cleanup) })

	require.NotEmpty(t, cleanup, "a temp archive must report a cleanup path")
	assert.Equal(t, name, cleanup)
	assert.Zero(t, skipped.Total)

	// An agent killed mid-download leaves this behind, and a bare UUID gives
	// nobody a way to tell whose file it is.
	assert.True(t, strings.HasPrefix(filepath.Base(name), "alpamon-webftp-"),
		"temp archive %q does not name its owner", filepath.Base(name))

	// The archive holds whatever the requested tree held and it sits in
	// os.TempDir(), so it must not be readable by everyone.
	info, err := os.Stat(name)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), info.Mode().Perm())

	r, err := zip.OpenReader(name)
	require.NoError(t, err)
	defer func() { _ = r.Close() }()
	require.Len(t, r.File, 1)
	assert.Equal(t, "tree/a.txt", r.File[0].Name)
}

func TestMakeArchive_ReportsWhatItCouldNotRead(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads a 0000 directory whatever its mode says")
	}

	// CreateZip resolves the listed root before walking, so the paths it
	// reports are resolved too. On darwin t.TempDir() sits under /var, which is
	// a link to /private/var, and an unresolved expectation would never match.
	dir, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)
	tree := filepath.Join(dir, "tree")
	require.NoError(t, os.MkdirAll(tree, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(tree, "readable.txt"), []byte("r"), 0644))
	locked := filepath.Join(tree, "locked")
	require.NoError(t, os.MkdirAll(locked, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(locked, "secret.txt"), []byte("s"), 0644))
	require.NoError(t, os.Chmod(locked, 0000))
	t.Cleanup(func() { _ = os.Chmod(locked, 0755) })

	h := &FileHandler{}
	name, cleanup, skipped, err := h.makeArchive(context.Background(), []string{tree}, false, true, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.Remove(cleanup) })

	// What the walk could not enter has to reach uploadSummary, or a partial
	// archive reads as a complete one.
	assert.Equal(t, 1, skipped.Total)
	require.Len(t, skipped.Entries, 1)
	assert.Equal(t, locked, skipped.Entries[0].Path)

	r, err := zip.OpenReader(name)
	require.NoError(t, err)
	defer func() { _ = r.Close() }()
	require.Len(t, r.File, 1)
	assert.Equal(t, "tree/readable.txt", r.File[0].Name)
}

func TestMakeArchive_LeavesASingleFileAlone(t *testing.T) {
	dir := t.TempDir()
	single := filepath.Join(dir, "one.txt")
	require.NoError(t, os.WriteFile(single, []byte("x"), 0644))

	h := &FileHandler{}
	name, cleanup, skipped, err := h.makeArchive(context.Background(), []string{single}, false, false, nil)

	require.NoError(t, err)
	// No archive is built, so the caller must not be handed a cleanup path,
	// and readFileAs still reads this one as the requesting user.
	assert.Equal(t, single, name)
	assert.Empty(t, cleanup)
	assert.Zero(t, skipped.Total)
}
