//go:build linux

package utils

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCreateZip_CloseFailureIsReported(t *testing.T) {
	if _, err := os.Stat("/dev/full"); err != nil {
		t.Skip("/dev/full is not available")
	}

	src := filepath.Join(t.TempDir(), "file.txt")
	require.NoError(t, os.WriteFile(src, []byte("hi"), 0644))

	// /dev/full accepts the open and fails every write with ENOSPC. The
	// zip.Writer buffers, so a small entry only fails once Close flushes it
	// along with the central directory.
	err := CreateZip("/dev/full", []string{src}, false)
	assert.ErrorContains(t, err, "no space left on device")
}
