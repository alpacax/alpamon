package runner

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// macOS has no seal API, so the copy's protection is that nothing can name it.
// This is the property sealFile checks, and the one the requester cannot get
// around: it knows only the original path.
func TestSealedFile_IsNameless(t *testing.T) {
	sealed, err := newSealedFile()
	require.NoError(t, err)
	t.Cleanup(func() { _ = sealed.Close() })

	_, err = sealed.WriteString("printf 'original\\n'\n")
	require.NoError(t, err)
	require.NoError(t, sealFile(sealed))

	info, err := sealed.Stat()
	require.NoError(t, err)
	stat, ok := info.Sys().(*syscall.Stat_t)
	require.True(t, ok)
	assert.Zero(t, stat.Nlink, "the copy must have no directory entry left")

	_, err = os.Stat(sealed.Name())
	assert.Error(t, err, "the copy must not be reachable by any path")
}

// sealFile refuses rather than reporting success when the object still has a
// name: a linked file is one the requester could reach, which is the window
// the copy exists to close.
func TestSealedFile_RefusesAStillLinkedObject(t *testing.T) {
	path := filepath.Join(t.TempDir(), "linked.sh")
	require.NoError(t, os.WriteFile(path, []byte("printf 'x\\n'\n"), 0o600))
	file, err := os.OpenFile(path, os.O_RDWR, 0)
	require.NoError(t, err)
	t.Cleanup(func() { _ = file.Close() })

	err = sealFile(file)

	require.Error(t, err)
	assert.ErrorIs(t, err, errSealUnavailable)
}
