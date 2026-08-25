//go:build !windows

package utils

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestOpenIfZip_RefusesASymlink pins the O_NOFOLLOW open. The extract path
// re-opens a file the requesting user just wrote, and the agent does that as
// root, so a symlink raced in at that path must not be dereferenced. Without
// O_NOFOLLOW the open follows the link and hands back a valid zip the user
// could not have read; with it the open fails and OpenIfZip returns nil, so
// nothing is extracted.
func TestOpenIfZip_RefusesASymlink(t *testing.T) {
	dir := t.TempDir()

	// A real, valid zip standing in for a target the requesting user cannot
	// reach. Opening it directly still works, so the refusal below is the
	// symlink being rejected, not the zip being unreadable.
	target := filepath.Join(dir, "target.zip")
	writeEntryZip(t, target, nil)
	if f := OpenIfZip(target, ".zip"); assert.NotNil(t, f, "the target zip must open on its own") {
		_ = f.Close()
	}

	link := filepath.Join(dir, "link.zip")
	require.NoError(t, os.Symlink(target, link))

	if f := OpenIfZip(link, ".zip"); !assert.Nil(t, f, "a symlink at the source path must be refused") {
		_ = f.Close()
	}
}
