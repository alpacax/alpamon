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
	ctx := commandgroup.WithStartLock(t.Context(), &lock)
	cmd := exec.CommandContext(ctx, "/bin/true")
	// A nil cleanup panics inside afterStart. Its Unix close method is a no-op.
	require.Panics(t, func() { _, _ = runTrackedCommand(ctx, cmd, nil, nil, nil, "") })
	require.NotNil(t, cmd.Process)
	require.NoError(t, cmd.Wait())
	require.True(t, lock.TryLock())
	lock.Unlock()
}
