package runner

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func TestSealedFile_RejectsWritesOnceSealed(t *testing.T) {
	sealed, err := newSealedFile()
	require.NoError(t, err)
	t.Cleanup(func() { _ = sealed.Close() })

	_, err = sealed.WriteString("printf 'original\\n'\n")
	require.NoError(t, err, "the copy must be writable until it is sealed")

	require.NoError(t, sealFile(sealed))

	// The seal binds every descriptor for this object, this one included, so
	// there is no handle left anywhere that can change what runs.
	_, err = sealed.WriteAt([]byte("x"), 0)
	assert.Error(t, err, "a sealed copy must reject writes")
}

func TestSealedFile_AppliesEverySeal(t *testing.T) {
	sealed, err := newSealedFile()
	require.NoError(t, err)
	t.Cleanup(func() { _ = sealed.Close() })

	require.NoError(t, sealFile(sealed))

	applied, err := unix.FcntlInt(sealed.Fd(), unix.F_GET_SEALS, 0)
	require.NoError(t, err)
	assert.Equal(t, verifiedFileSeals, applied&verifiedFileSeals,
		"write, shrink, grow and seal must all be set")
}

// A memfd has no name, so there is nothing for the requester to open, rename
// or rewrite—the property the seal complements rather than replaces.
func TestSealedFile_HasNoNameInTheFilesystem(t *testing.T) {
	sealed, err := newSealedFile()
	require.NoError(t, err)
	t.Cleanup(func() { _ = sealed.Close() })

	_, err = os.Stat(sealed.Name())
	assert.Error(t, err, "the copy must not be reachable by any path")
}

// sealFile refuses rather than reporting success when the object cannot
// actually be sealed: a regular file accepts no seals, and treating that as
// sealed would put the rewrite window straight back.
func TestSealedFile_RefusesToSealAnUnsealableObject(t *testing.T) {
	path := filepath.Join(t.TempDir(), "regular.sh")
	require.NoError(t, os.WriteFile(path, []byte("printf 'x\\n'\n"), 0o600))
	file, err := os.OpenFile(path, os.O_RDWR, 0)
	require.NoError(t, err)
	t.Cleanup(func() { _ = file.Close() })

	err = sealFile(file)

	require.Error(t, err)
	assert.ErrorIs(t, err, errSealUnavailable)
}
