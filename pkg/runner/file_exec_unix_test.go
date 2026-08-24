//go:build !windows

package runner

import (
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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

// A refusal is reported to the requester as the command result, and the
// requester chose the path. Returning what the file hashed to would make the
// refusal itself a disclosure: the assessor judges the submitted content, so a
// benign script paired with a path like /etc/shadow auto-approves, mismatches,
// and hands back the digest of a file the requester may not read.
func TestOpenVerifiedFile_MismatchNeverReportsTheObservedDigest(t *testing.T) {
	secret := []byte("root-only secret\n")
	path := filepath.Join(t.TempDir(), "secret")
	require.NoError(t, os.WriteFile(path, secret, 0o600))
	observed := fmt.Sprintf("%x", sha256.Sum256(secret))
	approved := strings.Repeat("b", 64)

	_, err := openVerifiedFile(path, approved)

	require.Error(t, err)
	require.ErrorIs(t, err, errHashMismatch)
	assert.NotContains(t, err.Error(), observed,
		"the refusal must not disclose what the file hashed to")
	// The expected digest came from the requester, so echoing it tells them
	// nothing they did not already send.
	assert.Contains(t, err.Error(), approved)
}

// The operator still needs the real value to diagnose a genuine mismatch; it
// travels on the error type for the local log rather than in Error().
func TestHashMismatchError_CarriesTheObservedDigestForTheLog(t *testing.T) {
	secret := []byte("root-only secret\n")
	path := filepath.Join(t.TempDir(), "secret")
	require.NoError(t, os.WriteFile(path, secret, 0o600))
	observed := fmt.Sprintf("%x", sha256.Sum256(secret))

	_, err := openVerifiedFile(path, strings.Repeat("b", 64))

	var mismatch *hashMismatchError
	require.ErrorAs(t, err, &mismatch)
	assert.Equal(t, observed, mismatch.Observed())
}
