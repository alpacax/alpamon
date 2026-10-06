//go:build linux

package updater

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func useTempUpgradeLock(t *testing.T) string {
	t.Helper()
	orig := upgradeLockPath
	upgradeLockPath = filepath.Join(t.TempDir(), "run", "upgrade.lock")
	t.Cleanup(func() {
		ReleaseSelfUpdateLatch()
		upgradeLockPath = orig
	})
	return upgradeLockPath
}

func flockFile(t *testing.T, path string) error {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o750))
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	require.NoError(t, err)
	t.Cleanup(func() { _ = f.Close() })
	return syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
}

func TestAcquireUpgradeLatchFailsWhileAnotherProcessHoldsTheUpgradeLock(t *testing.T) {
	// Given another open file description holding the cross-process lock
	path := useTempUpgradeLock(t)
	err := flockFile(t, path)
	require.NoError(t, err)

	// When the latch is acquired
	got := AcquireUpgradeLatch()

	// Then it is refused and the in-process flag stays clear
	assert.False(t, got)
	assert.False(t, selfUpdateInFlight.Load())
}

func TestSelfUpdateReturnsInProgressWhileAnotherProcessHoldsTheUpgradeLock(t *testing.T) {
	// Given another open file description holding the cross-process lock
	path := useTempUpgradeLock(t)
	err := flockFile(t, path)
	require.NoError(t, err)

	// When a self-update starts
	err = SelfUpdate(t.Context(), "v1.0.0", Options{})

	// Then it reports an upgrade in progress
	assert.ErrorIs(t, err, ErrSelfUpdateInProgress)
}

func TestAcquireUpgradeLatchHoldsTheUpgradeLockUntilReleased(t *testing.T) {
	// Given a free lock
	path := useTempUpgradeLock(t)

	// When the latch is acquired
	require.True(t, AcquireUpgradeLatch())

	// Then another holder cannot take the lock
	err := flockFile(t, path)
	assert.ErrorIs(t, err, syscall.EWOULDBLOCK)

	// And after release it can
	ReleaseSelfUpdateLatch()
	err = flockFile(t, path)
	assert.NoError(t, err)
}
