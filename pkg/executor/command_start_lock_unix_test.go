//go:build !windows

package executor

import (
	"os/exec"
	"sync"
	"testing"

	"github.com/alpacax/alpamon/v2/internal/commandgroup"
	"github.com/stretchr/testify/require"
)

func TestAfterStartPanicReleasesStartLock(t *testing.T) {
	var lock sync.RWMutex
	var acquired bool
	ctx := commandgroup.WithStartHook(t.Context(), func(string) func() {
		lock.Lock()
		acquired = true
		return lock.Unlock
	})
	binary, err := exec.LookPath("true")
	require.NoError(t, err)
	cmd := exec.CommandContext(ctx, binary)
	// A nil cleanup panics inside afterStart. Its Unix close method is a no-op.
	require.Panics(t, func() { _, _ = runTrackedCommand(ctx, cmd, nil, nil, nil, "") })
	require.NotNil(t, cmd.Process)
	require.NoError(t, cmd.Wait())
	require.True(t, acquired, "the start hook must acquire the lock")
	require.True(t, lock.TryLock())
	lock.Unlock()
}
