//go:build !windows

package runner

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/alpacax/alpamon/v2/pkg/executor/handlers/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// runVerifiedFile executes the copy openVerifiedFile returned, the way the
// executor does: inherited at VerifiedFileChildFD and named by its descriptor
// path, never by the path it came from.
func runVerifiedFile(t *testing.T, sealed *os.File) string {
	t.Helper()

	fdPath, err := common.VerifiedFilePath()
	require.NoError(t, err)

	cmd := exec.Command("/bin/sh", fdPath)
	cmd.ExtraFiles = []*os.File{sealed}
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "output was %q", string(out))

	return string(out)
}

// runPath executes the script the path currently names, as a control for what
// a path-based implementation would have run.
func runPath(t *testing.T, path string) string {
	t.Helper()

	out, err := exec.Command("/bin/sh", path).CombinedOutput()
	require.NoError(t, err, "output was %q", string(out))

	return string(out)
}

// TestOpenVerifiedFile_InPlaceRewriteExecutesVerifiedBytes is the end-to-end
// form of the case the sealed copy closes: the requester rewrites its own file
// in place after the digest matched, and the child still runs what was
// approved. The control at the end proves the rewrite really landed, so the
// test cannot pass by the rewrite silently failing.
func TestOpenVerifiedFile_InPlaceRewriteExecutesVerifiedBytes(t *testing.T) {
	skipIfNoVerifiedFileExec(t)

	original := []byte("printf 'ORIGINAL\\n'\n")
	rewritten := []byte("printf 'REWRITE!\\n'\n")
	require.Len(t, rewritten, len(original))

	path := filepath.Join(t.TempDir(), "deploy.sh")
	require.NoError(t, os.WriteFile(path, original, 0o700))

	sealed, err := openVerifiedFile(path, hexDigest(original))
	require.NoError(t, err)
	t.Cleanup(func() { _ = sealed.Close() })

	rewriteInPlace(t, path, rewritten)

	assert.Equal(t, "ORIGINAL\n", runVerifiedFile(t, sealed),
		"the executed bytes must be the verified ones")
	require.Equal(t, "REWRITE!\n", runPath(t, path),
		"the in-place rewrite must be live or this test proves nothing")
}

// The replace-at-the-path case, end to end through the same production path.
func TestOpenVerifiedFile_SwapExecutesVerifiedBytes(t *testing.T) {
	skipIfNoVerifiedFileExec(t)

	dir := t.TempDir()
	path := filepath.Join(dir, "deploy.sh")
	original := []byte("printf 'ORIGINAL\\n'\n")
	require.NoError(t, os.WriteFile(path, original, 0o700))

	sealed, err := openVerifiedFile(path, hexDigest(original))
	require.NoError(t, err)
	t.Cleanup(func() { _ = sealed.Close() })

	decoy := filepath.Join(dir, "decoy.sh")
	require.NoError(t, os.WriteFile(decoy, []byte("printf 'SWAPPED\\n'\n"), 0o700))
	require.NoError(t, os.Rename(decoy, path))

	assert.Equal(t, "ORIGINAL\n", runVerifiedFile(t, sealed))
	require.Equal(t, "SWAPPED\n", runPath(t, path),
		"the swap must be live or this test proves nothing")
}

// Deleting the original entirely leaves the approved bytes runnable: the copy
// never depended on the path.
func TestOpenVerifiedFile_SurvivesDeletionOfTheOriginal(t *testing.T) {
	skipIfNoVerifiedFileExec(t)

	original := []byte("printf 'ORIGINAL\\n'\n")
	path := filepath.Join(t.TempDir(), "deploy.sh")
	require.NoError(t, os.WriteFile(path, original, 0o700))

	sealed, err := openVerifiedFile(path, hexDigest(original))
	require.NoError(t, err)
	t.Cleanup(func() { _ = sealed.Close() })

	require.NoError(t, os.Remove(path))

	assert.Equal(t, "ORIGINAL\n", runVerifiedFile(t, sealed))
}
