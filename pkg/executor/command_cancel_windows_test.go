package executor

import (
	"context"
	"os/exec"
	"testing"
	"time"

	"github.com/alpacax/alpamon/v2/internal/commandcancel"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRemoteCancelWindowsJobTree(t *testing.T) {
	ctx, state := commandcancel.NewContext(context.Background())
	defer state.Cancel()
	cmd := exec.CommandContext(ctx, "cmd", "/c", "ping", "-n", "60", "127.0.0.1")
	started := make(chan int, 1)
	done := make(chan error, 1)
	go func() {
		_, err := NewExecutor().runCommand(ctx, cmd, "remote", func(pid int) { started <- pid }, nil)
		done <- err
	}()
	var root int
	select {
	case root = <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("command did not start")
	}
	child := waitForWindowsChild(t, uint32(root), "ping.exe")
	state.Cancel()
	select {
	case err := <-done:
		require.Error(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("cancel did not finish")
	}
	cancelled, survivors := state.Finish()
	assert.True(t, cancelled)
	assert.Empty(t, survivors)
	waitForWindowsPidGone(t, uint32(root), "cancelled root")
	waitForWindowsPidGone(t, child, "cancelled child")
}
