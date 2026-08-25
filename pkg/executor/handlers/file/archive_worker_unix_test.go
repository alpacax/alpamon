//go:build !windows

package file

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestArchiveWorkerResult_CarriesTheSkippedList(t *testing.T) {
	status := `{"skipped":[{"path":"/root/secret","reason":"permission denied"}]}`

	skipped, err := archiveWorkerResult(status, nil)

	require.NoError(t, err)
	require.Len(t, skipped, 1)
	assert.Equal(t, "/root/secret", skipped[0].Path)
	// uploadSummary prints the reason, so it has to survive as an error value.
	assert.EqualError(t, skipped[0].Reason, "permission denied")
}

func TestArchiveWorkerResult_ReportsTheWorkerErrorWithWhatWasSkipped(t *testing.T) {
	status := `{"skipped":[{"path":"/root","reason":"permission denied"}],` +
		`"error":"nothing could be archived, skipped 1 path(s): permission denied"}`

	// A user who asks for a directory they cannot read must get the failure,
	// not an empty archive reported as a finished download.
	skipped, err := archiveWorkerResult(status, errors.New("exit status 1"))

	assert.ErrorContains(t, err, "nothing could be archived")
	assert.Len(t, skipped, 1)
}

func TestArchiveWorkerResult_FallsBackToTheRawStreamWhenTheWorkerDied(t *testing.T) {
	// A worker killed before it could encode leaves the stream unparseable,
	// and swallowing that would report a truncated archive as a success.
	skipped, err := archiveWorkerResult("signal: killed", errors.New("exit status 2"))

	assert.ErrorContains(t, err, "exit status 2")
	assert.ErrorContains(t, err, "signal: killed")
	assert.Empty(t, skipped)
}

func TestArchiveWorkerResult_RejectsAnUnparseableStatusOnASilentExit(t *testing.T) {
	// Exit 0 with a status nobody can read means the archive is unaccounted
	// for; treating it as an empty skipped list would hide that.
	_, err := archiveWorkerResult("", nil)

	assert.ErrorContains(t, err, "failed to read the archive worker status")
}
