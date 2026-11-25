package commandcancel

import (
	"os/exec"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPidfdSignalsReachAVerifiedProcess(t *testing.T) {
	if !PinnedSignalsHeld() {
		t.Skip("this kernel has no pidfd")
	}
	cmd := exec.Command("sleep", "60")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	require.NoError(t, cmd.Start())
	pid := cmd.Process.Pid
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	started, err := ProcessStartTime(pid)
	require.NoError(t, err)

	groups, err := SignalPinnedSessionMembers(pid, map[int]SessionMember{pid: {StartedAt: started, PGID: pid}}, syscall.SIGKILL)
	require.NoError(t, err)
	assert.Equal(t, []int{pid}, groups)
	state, err := cmd.Process.Wait()
	require.NoError(t, err)
	assert.Equal(t, syscall.SIGKILL, state.Sys().(syscall.WaitStatus).Signal())

	groups, err = SignalPinnedSessionMembers(pid, map[int]SessionMember{pid: {StartedAt: started, PGID: pid}}, syscall.SIGKILL)
	require.NoError(t, err, "a reaped member is gone")
	assert.Empty(t, groups)
}
